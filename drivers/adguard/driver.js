'use strict';

const Homey = require('homey');
const axios = require('axios');

module.exports = class AdGuardHomeDriver extends Homey.Driver {

  /**
   * onInit is called when the driver is initialized.
   * Flow cards are registered here (once), and the device is taken from args.device,
   * so every card works with more than one AdGuard Home server.
   */
  async onInit() {
    this.log('AdGuard Home driver has been initialized');
    const { flow } = this.homey;

    // Triggers with a feature argument only fire for the selected feature
    const featureMatches = async (args, state) => args.feature === state.feature;
    flow.getDeviceTriggerCard('feature_turned_on').registerRunListener(featureMatches);
    flow.getDeviceTriggerCard('feature_turned_off').registerRunListener(featureMatches);

    // Conditions
    flow.getConditionCard('protection_condition')
      .registerRunListener(async ({ device }) => device.getCapabilityValue('protection') === true);
    flow.getConditionCard('feature_condition')
      .registerRunListener(async ({ device, feature }) => device.getFeatureState(feature));
    flow.getConditionCard('domain_blocked')
      .registerRunListener(async ({ device, domain }) => device.isDomainBlocked(domain));

    // Actions
    const action = (id, fn) => flow.getActionCard(id).registerRunListener(fn);
    action('enable_protection', ({ device }) => device.setProtection(true));
    action('disable_protection', ({ device }) => device.setProtection(false));
    action('pause_protection', ({ device, minutes }) => device.setProtection(false, minutes * 60 * 1000));
    action('feature_set', ({ device, feature, state }) => device.setFeature(feature, state === 'on'));
    action('block_domain', ({ device, domain }) => device.setDomainRule(domain, 'block'));
    action('allow_domain', ({ device, domain }) => device.setDomainRule(domain, 'allow'));
    action('remove_domain_rule', ({ device, domain }) => device.setDomainRule(domain, null));
    action('add_custom_rule', ({ device, rule }) => device.addCustomRule(rule));
    action('remove_custom_rule', ({ device, rule }) => device.removeCustomRule(rule.id));
    action('add_filter_list', ({ device, type, name, url }) => device.addFilterList(name, url, type === 'allow'));
    action('remove_filter_list', ({ device, list }) => device.removeFilterList(list.url, list.whitelist));
    action('set_filter_list', ({ device, list, state }) => device.setFilterListEnabled(list.url, list.whitelist, state === 'on'));
    action('update_blocklists', ({ device }) => device.updateLists(false));
    action('update_whitelists', ({ device }) => device.updateLists(true));
    action('reset_stats', ({ device }) => device.resetStats());

    // Autocomplete
    const listAutocomplete = async (query, { device }) => {
      const lists = await device.getFilterLists();
      const q = (query || '').toLowerCase();
      return lists
        .filter((l) => !q || l.name.toLowerCase().includes(q) || l.url.toLowerCase().includes(q))
        .map((l) => ({
          name: l.name || l.url,
          description: `${l.whitelist ? 'Allowlist' : 'Blocklist'} · ${l.enabled ? 'on' : 'off'} · ${l.url}`,
          url: l.url,
          whitelist: l.whitelist,
        }));
    };
    flow.getActionCard('remove_filter_list').registerArgumentAutocompleteListener('list', listAutocomplete);
    flow.getActionCard('set_filter_list').registerArgumentAutocompleteListener('list', listAutocomplete);

    flow.getActionCard('remove_custom_rule').registerArgumentAutocompleteListener('rule', async (query, { device }) => {
      const rules = await device.getCustomRules();
      const q = (query || '').toLowerCase();
      return rules
        .filter((r) => r.trim() && !r.trim().startsWith('!') && !r.trim().startsWith('#'))
        .filter((r) => !q || r.toLowerCase().includes(q))
        .slice(0, 50)
        .map((r) => ({ name: r, id: r }));
    });
  }

  triggerFlow(card, device, tokens = {}, state = {}) {
    this.homey.flow.getDeviceTriggerCard(card)
      .trigger(device, tokens, state)
      .catch((err) => this.error(`Failed to trigger ${card}:`, err.message));
  }

  async onPair(session) {
    session.setHandler('ip', async (data) => {
      this._ip = String(data.ip || '').trim();
      this._port = Number(data.port) || 80;
      const baseUrl = this._port === 80 ? `http://${this._ip}` : `http://${this._ip}:${this._port}`;
      this._baseUrl = baseUrl;
      this.log('Checking AdGuard Home at', baseUrl);
      try {
        await axios.get(`${baseUrl}/control/status`, { timeout: 5000 });
        // No authentication configured on this server: the device can be added right away
        return { ip: this._ip, baseUrl };
      } catch (error) {
        if (error?.response?.status === 401 || error?.response?.status === 403) {
          await session.showView('login');
          return true;
        }
        this.error('Error during IP check:', error.message);
        return false;
      }
    });

    session.setHandler('login', async (data) => {
      const basicAuth = Buffer.from(`${data.user}:${data.pass}`).toString('base64');
      this.log('Checking credentials for user', data.user, 'at', this._baseUrl);
      try {
        await axios.get(`${this._baseUrl}/control/stats`, {
          timeout: 5000,
          headers: { Authorization: `Basic ${basicAuth}` },
        });
        return {
          ip: this._ip, baseUrl: this._baseUrl, user: data.user, pass: data.pass,
        };
      } catch (error) {
        if (error.response?.status === 401 || error.response?.status === 403) {
          this.error('Authentication failed');
          return false;
        }
        throw new Error('Connection error');
      }
    });
  }

};
