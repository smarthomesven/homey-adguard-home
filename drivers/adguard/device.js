'use strict';

const Homey = require('homey');
const axios = require('axios');
const http = require('http');

// Capability IDs from app versions before 1.4.0, renamed with a measure_ prefix so that
// Homey offers them as status indicator.
const RENAMED_CAPABILITIES = {
  total_queries: 'measure_dns_queries',
  blocked_filtering: 'measure_blocked_filtering',
  blocked_adult: 'measure_blocked_parental',
  blocked_malware: 'measure_blocked_safebrowsing',
  blocked_safesearch: 'measure_blocked_safesearch',
};

// Counter capability -> { stats field, trigger card }
const COUNTERS = {
  measure_dns_queries: { field: 'num_dns_queries', trigger: 'total_queries_changed' },
  measure_blocked_filtering: { field: 'num_blocked_filtering', trigger: 'blocked_filtering_changed' },
  measure_blocked_parental: { field: 'num_replaced_parental', trigger: 'blocked_adult_changed' },
  measure_blocked_safebrowsing: { field: 'num_replaced_safebrowsing', trigger: 'blocked_malware_changed' },
  measure_blocked_safesearch: { field: 'num_replaced_safesearch', trigger: 'blocked_safesearch_changed' },
};

// Feature switches (the same set Home Assistant exposes)
const FEATURES = {
  filtering: 'filtering_enabled',
  parental: 'parental_enabled',
  safesearch: 'safesearch_enabled',
  safebrowsing: 'safebrowsing_enabled',
  querylog: 'querylog_enabled',
};

const DOMAIN_RE = /^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;

module.exports = class AdGuardHomeDevice extends Homey.Device {

  async onInit() {
    this._httpAgent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: 10000,
      maxSockets: 10,
      maxFreeSockets: 4,
      timeout: 15000,
    });
    if (!this.getStoreValue('baseUrl')) {
      await this.setStoreValue('baseUrl', `http://${this.getStoreValue('ip')}`);
    }
    this._apiClient = axios.create({
      baseURL: this.getStoreValue('baseUrl'),
      httpAgent: this._httpAgent,
      timeout: 10000,
    });
    const user = this.getStoreValue('user');
    const pass = this.getStoreValue('pass');
    this._authHeaders = user
      ? { Authorization: `Basic ${Buffer.from(`${user}:${pass || ''}`).toString('base64')}` }
      : {};

    await this._migrateCapabilities();

    this.registerCapabilityListener('protection', (value) => this.setProtection(value));
    for (const [feature, capability] of Object.entries(FEATURES)) {
      this.registerCapabilityListener(capability, (value) => this.setFeature(feature, value));
    }

    this._startPolling();
    this.log('AdGuard Home device has been initialized');
  }

  /* ------------------------------------------------------------------ */
  /* Setup                                                              */
  /* ------------------------------------------------------------------ */

  async _migrateCapabilities() {
    const wanted = this.driver.manifest.capabilities;
    for (const capability of wanted) {
      if (!this.hasCapability(capability)) {
        try {
          await this.addCapability(capability);
        } catch (err) {
          this.error(`Could not add capability ${capability}:`, err.message);
        }
      }
    }
    for (const oldCapability of Object.keys(RENAMED_CAPABILITIES)) {
      if (this.hasCapability(oldCapability)) {
        try {
          await this.removeCapability(oldCapability);
        } catch (err) {
          this.error(`Could not remove capability ${oldCapability}:`, err.message);
        }
      }
    }
  }

  _startPolling() {
    if (this._pollTimer) this.homey.clearInterval(this._pollTimer);
    const seconds = Math.max(5, Number(this.getSetting('poll_interval')) || 10);
    this._pollTimer = this.homey.setInterval(() => this.pollAdguard(), seconds * 1000);
    this.pollAdguard();
  }

  _stopPolling() {
    if (this._pollTimer) this.homey.clearInterval(this._pollTimer);
    this._pollTimer = null;
  }

  /* ------------------------------------------------------------------ */
  /* HTTP                                                               */
  /* ------------------------------------------------------------------ */

  async _api(method, path, data, params) {
    const response = await this._apiClient.request({
      method, url: path, data, params, headers: this._authHeaders,
    });
    return response.data;
  }

  // Wraps an API call so a failing flow card shows a readable message
  async _run(description, fn) {
    try {
      const result = await fn();
      this.log(`${description}: ok`);
      return result;
    } catch (error) {
      const body = error.response?.data;
      const text = typeof body === 'string' ? body : body ? JSON.stringify(body) : '';
      const detail = text.trim() ? ` (${text.trim().slice(0, 200)})` : '';
      this.error(`${description} failed:`, error.message, detail);
      throw new Error(`${description} failed: ${error.message}${detail}`);
    }
  }

  /* ------------------------------------------------------------------ */
  /* Polling                                                            */
  /* ------------------------------------------------------------------ */

  async pollAdguard() {
    if (this._polling) return; // previous poll still running (slow server)
    this._polling = true;
    try {
      let status;
      try {
        status = await this._api('get', '/control/status');
      } catch (error) {
        this.error('Error polling AdGuard Home:', error.message);
        const message = error.response?.status === 401
          ? 'AdGuard Home rejected the username or password'
          : 'Could not connect to AdGuard Home';
        await this.setUnavailable(message).catch(this.error);
        return;
      }
      await this.setAvailable().catch(this.error);

      await this._updateProtection(status.protection_enabled === true);
      if (status.version && status.version !== this._version) {
        this._version = status.version;
        await this.setSettings({ adguard_version: String(status.version) }).catch(this.error);
      }

      const [stats, filtering, safebrowsing, parental, safesearch, querylog] = await Promise.allSettled([
        this._api('get', '/control/stats'),
        this._api('get', '/control/filtering/status'),
        this._api('get', '/control/safebrowsing/status'),
        this._api('get', '/control/parental/status'),
        this._api('get', '/control/safesearch/status'),
        this._getQueryLogConfig(),
      ]);

      if (stats.status === 'fulfilled') await this._updateStats(stats.value);
      else this.error('Error polling stats:', stats.reason.message);

      if (filtering.status === 'fulfilled') {
        this._filteringStatus = filtering.value;
        await this._updateFeature('filtering', filtering.value.enabled);
        const rules = [...(filtering.value.filters || []), ...(filtering.value.whitelist_filters || [])]
          .filter((f) => f.enabled)
          .reduce((sum, f) => sum + (Number(f.rules_count) || 0), 0);
        await this._setNumber('measure_rules_count', rules);
      }
      if (safebrowsing.status === 'fulfilled') await this._updateFeature('safebrowsing', safebrowsing.value.enabled);
      if (parental.status === 'fulfilled') await this._updateFeature('parental', parental.value.enabled);
      if (safesearch.status === 'fulfilled') await this._updateFeature('safesearch', safesearch.value.enabled);
      if (querylog.status === 'fulfilled') await this._updateFeature('querylog', querylog.value.enabled);
    } catch (error) {
      this.error('Error in pollAdguard:', error.message);
    } finally {
      this._polling = false;
    }
  }

  async _updateProtection(isEnabled) {
    const previous = this.getCapabilityValue('protection');
    await this.setCapabilityValue('protection', isEnabled).catch(this.error);
    if (this._firstPollDone && previous !== null && previous !== isEnabled) {
      this.driver.triggerFlow(isEnabled ? 'protection_enabled' : 'protection_disabled', this);
    }
    this._firstPollDone = true;
  }

  async _updateFeature(feature, value) {
    if (typeof value !== 'boolean') return;
    const capability = FEATURES[feature];
    const previous = this.getCapabilityValue(capability);
    await this.setCapabilityValue(capability, value).catch(this.error);
    if (previous !== null && previous !== value) {
      this.driver.triggerFlow(value ? 'feature_turned_on' : 'feature_turned_off', this, {}, { feature });
    }
  }

  async _updateStats(data) {
    for (const [capability, { field, trigger }] of Object.entries(COUNTERS)) {
      const value = Number(data[field]);
      if (Number.isFinite(value)) await this._setNumber(capability, value, trigger);
    }
    const total = Number(data.num_dns_queries) || 0;
    const blocked = Number(data.num_blocked_filtering) || 0;
    const ratio = total > 0 ? Math.round((blocked / total) * 1000) / 10 : 0;
    await this._setNumber('measure_blocked_ratio', ratio, 'blocked_ratio_changed');
    const avg = Number(data.avg_processing_time); // seconds
    if (Number.isFinite(avg)) await this._setNumber('measure_processing_time', Math.round(avg * 10000) / 10);
  }

  async _setNumber(capability, value, trigger) {
    const previous = this.getCapabilityValue(capability);
    if (previous === value) return;
    await this.setCapabilityValue(capability, value).catch(this.error);
    if (trigger && previous !== null) this.driver.triggerFlow(trigger, this, { value });
  }

  /* ------------------------------------------------------------------ */
  /* Protection and feature switches                                    */
  /* ------------------------------------------------------------------ */

  /**
   * @param {boolean} enable
   * @param {number|null} [durationMs] when disabling: turn protection back on after this long
   */
  async setProtection(enable, durationMs = null) {
    const what = enable ? 'Enable protection' : `Disable protection${durationMs ? ` for ${durationMs / 60000} min` : ''}`;
    await this._run(what, () => this._api('post', '/control/protection', {
      enabled: enable,
      duration: enable ? null : durationMs,
    }));
    await this._updateProtection(enable);
  }

  getFeatureState(feature) {
    const capability = FEATURES[feature];
    if (!capability) throw new Error(`Unknown feature ${feature}`);
    return this.getCapabilityValue(capability) === true;
  }

  async setFeature(feature, enable) {
    const onoff = enable ? 'enable' : 'disable';
    await this._run(`Turn ${feature} ${enable ? 'on' : 'off'}`, async () => {
      switch (feature) {
        case 'filtering': {
          const status = await this._api('get', '/control/filtering/status');
          await this._api('post', '/control/filtering/config', { enabled: enable, interval: status.interval });
          break;
        }
        case 'safebrowsing':
          await this._api('post', `/control/safebrowsing/${onoff}`);
          break;
        case 'parental':
          await this._api('post', `/control/parental/${onoff}`);
          break;
        case 'safesearch': {
          const settings = await this._api('get', '/control/safesearch/status');
          try {
            await this._api('put', '/control/safesearch/settings', { ...settings, enabled: enable });
          } catch (error) {
            // AdGuard Home before v0.107.26 only has the enable/disable endpoints
            if (![404, 405].includes(error.response?.status)) throw error;
            await this._api('post', `/control/safesearch/${onoff}`);
          }
          break;
        }
        case 'querylog':
          await this._setQueryLogEnabled(enable);
          break;
        default:
          throw new Error(`Unknown feature ${feature}`);
      }
    });
    await this._updateFeature(feature, enable);
  }

  async _getQueryLogConfig() {
    try {
      return await this._api('get', '/control/querylog/config');
    } catch (error) {
      if (error.response?.status !== 404) throw error;
      return this._api('get', '/control/querylog_info'); // AdGuard Home before v0.107.30
    }
  }

  async _setQueryLogEnabled(enable) {
    const config = await this._getQueryLogConfig();
    try {
      await this._api('put', '/control/querylog/config/update', { ...config, enabled: enable });
    } catch (error) {
      if (![404, 405].includes(error.response?.status)) throw error;
      await this._api('post', '/control/querylog_config', { ...config, enabled: enable });
    }
  }

  /* ------------------------------------------------------------------ */
  /* Custom rules and domains                                           */
  /* ------------------------------------------------------------------ */

  static normalizeDomain(input) {
    let domain = String(input || '').trim().toLowerCase();
    domain = domain.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
    domain = domain.replace(/^\|\|/, '').replace(/\^.*$/, ''); // pasted rule syntax
    domain = domain.split(/[/?#:]/)[0].replace(/\.$/, '');
    if (!DOMAIN_RE.test(domain)) throw new Error(`"${input}" is not a valid domain`);
    return domain;
  }

  async getCustomRules() {
    const status = await this._api('get', '/control/filtering/status');
    return Array.isArray(status.user_rules) ? status.user_rules : [];
  }

  async _setCustomRules(rules) {
    await this._api('post', '/control/filtering/set_rules', { rules });
  }

  async addCustomRule(rule) {
    const value = String(rule || '').trim();
    if (!value) throw new Error('The rule is empty');
    await this._run(`Add custom rule ${value}`, async () => {
      const rules = await this.getCustomRules();
      if (!rules.includes(value)) await this._setCustomRules([...rules, value]);
    });
  }

  async removeCustomRule(rule) {
    const value = String(rule || '').trim();
    await this._run(`Remove custom rule ${value}`, async () => {
      const rules = await this.getCustomRules();
      if (rules.includes(value)) await this._setCustomRules(rules.filter((r) => r !== value));
    });
  }

  /**
   * Block, allow, or (mode null) clear the custom rules for a domain.
   * Replaces an opposite rule, so "block" after "allow" really blocks.
   */
  async setDomainRule(input, mode) {
    const domain = AdGuardHomeDevice.normalizeDomain(input);
    const blockRule = `||${domain}^`;
    const allowRule = `@@||${domain}^`;
    const label = mode === 'block' ? `Block ${domain}` : mode === 'allow' ? `Allow ${domain}` : `Remove rules for ${domain}`;
    await this._run(label, async () => {
      const rules = await this.getCustomRules();
      const next = rules.filter((r) => r.trim() !== blockRule && r.trim() !== allowRule);
      if (mode === 'block') next.push(blockRule);
      if (mode === 'allow') next.push(allowRule);
      await this._setCustomRules(next);
    });
  }

  async isDomainBlocked(input) {
    const domain = AdGuardHomeDevice.normalizeDomain(input);
    const result = await this._run(`Check ${domain}`, () => this._api('get', '/control/filtering/check_host', null, { name: domain }));
    // Reasons such as FilteredBlackList, FilteredSafeBrowsing, FilteredParental, FilteredBlockedService
    return typeof result.reason === 'string' && result.reason.startsWith('Filtered');
  }

  /* ------------------------------------------------------------------ */
  /* Filter lists                                                       */
  /* ------------------------------------------------------------------ */

  async getFilterLists() {
    const status = await this._api('get', '/control/filtering/status');
    const map = (whitelist) => (f) => ({
      name: f.name || '', url: f.url, enabled: !!f.enabled, whitelist,
    });
    return [
      ...(status.filters || []).map(map(false)),
      ...(status.whitelist_filters || []).map(map(true)),
    ];
  }

  async addFilterList(name, url, whitelist) {
    const listUrl = String(url || '').trim();
    if (!/^https?:\/\//i.test(listUrl) && !listUrl.startsWith('/')) {
      throw new Error('The URL must start with http:// or https:// (or be an absolute file path)');
    }
    await this._run(`Add filter list ${listUrl}`, () => this._api('post', '/control/filtering/add_url', {
      name: String(name || '').trim() || listUrl, url: listUrl, whitelist,
    }));
  }

  async removeFilterList(url, whitelist) {
    await this._run(`Remove filter list ${url}`, () => this._api('post', '/control/filtering/remove_url', { url, whitelist }));
  }

  async setFilterListEnabled(url, whitelist, enabled) {
    await this._run(`Turn filter list ${url} ${enabled ? 'on' : 'off'}`, async () => {
      const list = (await this.getFilterLists()).find((l) => l.url === url && l.whitelist === whitelist);
      if (!list) throw new Error('Filter list no longer exists');
      await this._api('post', '/control/filtering/set_url', {
        url, whitelist, data: { name: list.name, url, enabled },
      });
    });
  }

  async updateLists(whitelist) {
    await this._run(`Update ${whitelist ? 'allowlists' : 'blocklists'}`, () => this._api('post', '/control/filtering/refresh', { whitelist }));
  }

  async resetStats() {
    await this._run('Reset statistics', () => this._api('post', '/control/stats_reset'));
    this.pollAdguard();
  }

  /* ------------------------------------------------------------------ */
  /* Lifecycle                                                          */
  /* ------------------------------------------------------------------ */

  async onSettings({ changedKeys }) {
    if (changedKeys.includes('poll_interval')) {
      // Apply after the new settings are saved
      this.homey.setTimeout(() => this._startPolling(), 0);
    }
  }

  async onUninit() {
    this._stopPolling();
  }

  async onDeleted() {
    this._stopPolling();
    this.log('AdGuard Home device has been deleted');
  }

};
