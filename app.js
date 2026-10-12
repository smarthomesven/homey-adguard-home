'use strict';

const Homey = require('homey');
const axios = require('axios');
const HomeyPush = require('./lib/push');

module.exports = class AdguardHomeApp extends Homey.App {

  /**
   * onInit is called when the app is initialized.
   */
  async onInit() {
    this.log('AdGuard Home app has been initialized');
    this.push = new HomeyPush(this);
    await this.push.startPush();
  }

  async onUninit() {
    this.push.stopPush();
  }

};
