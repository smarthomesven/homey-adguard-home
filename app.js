'use strict';

const Homey = require('homey');
const axios = require('axios');

module.exports = class AdguardHomeApp extends Homey.App {

  /**
   * onInit is called when the app is initialized.
   */
  async onInit() {
    this.log('AdGuard Home app has been initialized');
  }

};
