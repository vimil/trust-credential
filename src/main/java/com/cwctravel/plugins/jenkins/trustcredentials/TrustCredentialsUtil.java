package com.cwctravel.plugins.jenkins.trustcredentials;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.common.collect.Iterables;

import hudson.model.Item;
import hudson.security.ACL;

public class TrustCredentialsUtil {
	private static final Logger LOGGER = Logger.getLogger(TrustCredentialsUtil.class.getName());

	public static void reloadTrustStores(TrustCredentialsImpl optional) {
		try {
			String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

			List<TrustCredentialsImpl> trustCredentials = CredentialsProvider.lookupCredentials(
					TrustCredentialsImpl.class, (Item) null, ACL.SYSTEM, Collections.<DomainRequirement>emptyList());

			X509TrustManager jvmTrustManager = getTrustManager(defaultAlgorithm, null);
			List<X509TrustManager> trustManagerList = new ArrayList<X509TrustManager>();
			trustManagerList.add(jvmTrustManager);
			if (optional != null) {
				X509TrustManager optionalTrustManager = getTrustManager("SunX509", optional.getKeyStore());
				trustManagerList.add(optionalTrustManager);
			}

			for (TrustCredentialsImpl trustCredentialsImpl : trustCredentials) {
				if (optional == null || !optional.getId().equals(trustCredentialsImpl.getId())) {
					KeyStore keystore = trustCredentialsImpl.getKeyStore();
					X509TrustManager customTrustManager = getTrustManager("SunX509", keystore);
					trustManagerList.add(customTrustManager);
				}
			}

			X509KeyManager jvmKeyManager = getKeyManager(defaultAlgorithm, null, null);
			KeyManager[] keyManagers = { jvmKeyManager };

			TrustManager[] trustManagers = { new CompositeX509TrustManager(trustManagerList) };

			SSLContext context = SSLContext.getInstance("TLS");
			context.init(keyManagers, trustManagers, null);
			HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
			SSLContext.setDefault(context);

		} catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
			LOGGER.log(Level.SEVERE, e.getMessage(), e);
		}
	}

	private static X509KeyManager getKeyManager(String algorithm, KeyStore keystore, char[] password)
			throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		KeyManagerFactory factory = KeyManagerFactory.getInstance(algorithm);
		factory.init(keystore, password);
		return Iterables.getFirst(Iterables.filter(Arrays.asList(factory.getKeyManagers()), X509KeyManager.class),
				null);
	}

	private static X509TrustManager getTrustManager(String algorithm, KeyStore keystore)
			throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory factory = TrustManagerFactory.getInstance(algorithm);
		factory.init(keystore);
		return Iterables.getFirst(Iterables.filter(Arrays.asList(factory.getTrustManagers()), X509TrustManager.class),
				null);
	}
}
