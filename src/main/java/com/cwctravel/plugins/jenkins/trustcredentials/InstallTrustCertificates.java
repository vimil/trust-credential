package com.cwctravel.plugins.jenkins.trustcredentials;

import java.util.logging.Logger;

import hudson.Extension;
import hudson.model.listeners.ItemListener;

@Extension
public class InstallTrustCertificates extends ItemListener {
	private static final Logger LOGGER = Logger.getLogger(InstallTrustCertificates.class.getName());

	@Override
	public void onLoaded() {
		TrustCredentialsUtil.reloadTrustStores(null);
	}

}
