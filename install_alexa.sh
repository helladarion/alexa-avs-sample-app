#!/bin/bash
# This script installs Amazon Alexa on raspberry pi 3 using 2017-03-02-raspbian-jessie
# Clonning the alexa repository
cd ~/Desktop
git clone https://github.com/alexa/alexa-avs-sample-app.git
# Fixing error for portaudio and including patch
cd ~/Desktop/alexa-avs-sample-app
sed -i "s_git clone https://github.com/Kitt-AI/snowboy.git_&\n\necho '========== Getting patch for Kitt-Ai ==========='\nmkdir -p snowboy/examples/C++/patches/ \&\& cd snowboy/examples/C++/patches/\nwget https://raw.githubusercontent.com/Kitt-AI/snowboy/10b53585407061ab72886a2c5b8542edc02364dc/examples/C%2B%2B/patches/portaudio.patch_" automated_install.sh
# Getting the data from user
leafpad automated_install.sh
# Starting installation
cd ~/Desktop/alexa-avs-sample-app
. automated_install.sh
# Creating autostart_alexa
FILE=~/Desktop/StartAlexa.sh
echo "cd ~/Desktop/alexa-avs-sample-app/samples" >> $FILE
echo "cd companionService && lxterminal -e npm start" >> $FILE
echo "sleep 10" >> $FILE
echo "cd ~/Desktop/alexa-avs-sample-app/samples" >> $FILE
echo "cd javaclient && lxterminal -e mvn exec:exec" >> $FILE
echo "sleep 70" >> $FILE
echo "cd ~/Desktop/alexa-avs-sample-app/samples" >> $FILE
echo "cd wakeWordAgent/src && lxterminal -e ./wakeWordAgent -e kitt_ai" >> $FILE
# Setting permission to execute the file
chmod +x ~/Desktop/StartAlexa.sh

# Implementing autoStart
function autoAlexa {
	read -p "Enter your Amazon email for Alexa: " email
	read -p "Enter your Amazon password for Alexa: " passwd
	
	#Installing phantonjs
	sudo apt-get install -y libfontconfig1 libfreetype6 libpng12-0;
	curl -o /tmp/phantomjs_2.1.1_armhf.deb -sSL https://github.com/fg2it/phantomjs-on-raspberry/releases/download/v2.1.1-wheezy-jessie/phantomjs_2.1.1_armhf.deb;
	sudo dpkg -i /tmp/phantomjs_2.1.1_armhf.deb;
		
	cd ~/Desktop/alexa-avs-sample-app
	cd samples/companionService/
	rm auth_automater.js

	cat << "EOF" | tee auth_automater.js
	"use strict";
	var system = require('system');
	var page = require('webpage').create();

	if (system.args.length != 2) {
		console.log('expecting a single argument, which is the authUrl to load, but got');
		system.args.forEach(function (arg, i) {
				console.log(i + ': ' + arg);
		});
		phantom.exit()
	}

	var authUrl = system.args[1];

	//Set the user agent, otherwise amazon thinks cookies are disabled
	page.settings.userAgent = "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.84 Safari/537.36";

	//Register sandboxed console.log calls to show up as phantomJS output
	page.onConsoleMessage = function(msg) {
		console.log('evaluate msg: ' + msg);
	};

	//Load the authUrl
	page.open(authUrl, function(){
	  
	  //Insert credentials
	  page.evaluate(function() {
		  var arr = document.getElementsByName("signIn");
		  var i;
		  console.log("Found this many elements with class 'signIn': "+ arr.length);
		  for (i=0; i < arr.length; i++) {
			if (arr[i].getAttribute('method') == "POST") {
			 console.log("Inserting creds");
			  arr[i].elements["ap_email"].value="INSERT_EMAIL_HERE";
			  arr[i].elements["ap_password"].value="INSERT_PASSWORD_HERE";
			 console.log("Done evaluating attempting to insert creds");
			  return;
			}
		  }
		});
	  
		//Submit the form
		page.evaluate(function() {
		   var arr = document.getElementsByName("signIn");
		   var i;
		   //TODO put this in the previous loop
		   for (i=0; i < arr.length; i++) {
			 if (arr[i].getAttribute('method') == "POST") {
			   arr[i].submit();
			   return;
			 }
		   }
		});
		//TODO see if we can make this not timing based.
		//Give phatomJS time to follow redirects and register the access token with the device
		setTimeout(function() {
			console.log("Exitting phantomJS");
		   phantom.exit();
		},7000);
	});
EOF

sed -i "s/INSERT_EMAIL_HERE/$email/" auth_automater.js
sed -i "s/INSERT_PASSWORD_HERE/$passwd/" auth_automater.js
	# -------
	cd ~/Desktop/alexa-avs-sample-app
	cd samples/companionService/

	rm authentication.js
	cat << "EOF" | tee authentication.js
	var crypto = require('crypto');
	var https = require('https');
	var uuid = require('node-uuid');
	var config = require("./config");
	var exec = require('child_process').execFile

	var auth = {};

	var sessionIds = [];
	var sessionIdToDeviceInfo = {};
	var regCodeToSessionId = {};
	var pendingStateToRegCode = {};
	var sessionIdToRefreshToken = {};

	var REG_NUM_BYTES = 12;
	var PRODUCT_MAX_LENGTH = 384;
	var PRODUCT_MIN_LENGTH = 1;
	var DSN_MIN_LENGTH = 1;

	var UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

	var oAuthServer = 'https://' + config.lwaRedirectHost + '/ap/oa';
	var lwaProdAuthUrl = oAuthServer + '?client_id=' + config.clientId + '&response_type=code&redirect_uri=' + config.redirectUrl;

	/**
	 * Create an error object to return to the user.
	 *
	 * @param name The name of the error.
	 * @param msg The message associated with the error.
	 * @param status The HTTP status code for the error.
	 * @returns The error.
	 */
	function error(name, msg, status) {
		var err = new Error();
		err.name = name;
		err.message = msg;
		err.status = status;
		return err;
	}

	/**
	 * Create an object of relevant LWA HTTP request information.
	 *
	 * @param urlPath The LWA host.
	 * @returns LWA HTTP request information.
	 */
	function getLwaPostOptions(urlPath) {
		return {
			host: config.lwaApiHost,
			path: urlPath,
			method: 'POST',
			port: 443,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
			},
			rejectUnauthorized: config.validateCertChain
		};
	}

	/**
	 * Redirect the user to the LWA page to authenticate.
	 *
	 * @param deviceInfo Device information including productId and dsn.
	 * @param regCode The regCode passed in from the user.
	 * @param res The HTTP response object.
	 */
	function redirectToDeviceAuthenticate(deviceInfo, regCode, res) {
		res.statusCode = 302;

		var state = uuid.v4();
		var productScope = {productID:deviceInfo.productId, productInstanceAttributes:{deviceSerialNumber:deviceInfo.dsn}};
		var scopeData = {};
		scopeData['alexa:all'] = productScope;

		var scopeDataStr = '&scope=' + encodeURIComponent('alexa:all') + '&state=' + encodeURIComponent(state) + '&scope_data=' + encodeURIComponent(JSON.stringify(scopeData));
		var authUrl = lwaProdAuthUrl + scopeDataStr;

		pendingStateToRegCode[state] = regCode;

		//res.setHeader("Location", authUrl);
		//Calling out to phantomJS to auth for us 
		var phantomExec = 'phantomjs';
		//Cookies file is there to enable cookies. Ignore ssl error on redirect back from amazon to localhost:3000
		var phantomExecArgs = ['--cookies-file=./cookies', '--ignore-ssl-errors=true', 'auth_automater.js' , authUrl];
		console.log("Calling out to phantomjs");
		console.log(authUrl);
		exec(phantomExec, phantomExecArgs , function(err, data) {  
			console.log(err)
			console.log(data.toString());                       
		});  

		res.end();
	}

	/**
	 * Determine if the user provided productId and dsn match the known map.
	 *
	 * @param productId The productId.
	 * @param dsn The dsn.
	 * @returns {Boolean}
	 */
	function isValidDevice(productId, dsn) {
		if (productId.length >= PRODUCT_MIN_LENGTH &&
			productId.length <= PRODUCT_MAX_LENGTH &&
			dsn.length >= DSN_MIN_LENGTH &&
			config.products[productId] &&
			config.products[productId].indexOf(dsn) >= 0) {
			return true;
		}

		return false;
	}

	/**
	 * Generate a registration code for a device, and map it to the device.
	 *
	 * The registration code is used by the user as a key to know what device to associate tokens with.
	 *
	 * @param productId The productId.
	 * @param dsn The dsn.
	 * @param callback The callback(err, json) to return data to the user.
	 */
	auth.getRegCode = function(productId, dsn, callback) {
		var missingProperties = [];
		if (!productId) {
			missingProperties.push("productId");
		}

		if (!dsn) {
			missingProperties.push("dsn");
		}

		if (missingProperties.length > 0) {
			callback(error("MissingParams", "The following parameters were missing or empty strings: " + missingProperties.join(", "), 400));
			return;
		}

		if (!isValidDevice(productId, dsn)) {
			callback(error("BadRequest", "The provided product and dsn do not match valid values", 400));
			return;
		}

		crypto.randomBytes(REG_NUM_BYTES, function(err, regCodeBuffer) {
			if (err) {
				console.log("failed on generate bytes", err);
				callback(error("InternalError", "Failure generating code", 500));
				return;
			} else {
				var regCode = regCodeBuffer.toString('hex');
				var sessionId = uuid.v4();
				sessionIds.push(sessionId);
				regCodeToSessionId[regCode] = sessionId;
				sessionIdToDeviceInfo[sessionId] = {
					productId: productId,
					dsn: dsn,
				};

				reply = {
					regCode: regCode,
					sessionId: sessionId,
				};

				callback(null, reply);
			}
		});
	};

	/**
	 * Get an accessToken associated with the sessionId.
	 *
	 * Makes a request to LWA to get accessToken given the stored refreshToken.
	 *
	 * @param sessionId The sessionId for this device.
	 * @param callback The callback(err, json) to return data to the user.
	 */
	auth.getAccessToken = function(sessionId, callback) {
		var missingProperties = [];
		if (!sessionId) {
			missingProperties.push("sessionId");
		}

		if (missingProperties.length > 0) {
			callback(error("MissingParams", "The following parameters were missing or empty strings: " + missingProperties.join(", "), 400));
			return;
		}

		if (sessionIds.indexOf(sessionId) == -1 || !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(sessionId)) {
			callback(error('InvalidSessionId', 'The provided sessionId was invalid.', 401));
			return;
		}

		if (!(sessionId in sessionIdToRefreshToken)) {
			callback(error('InvalidSessionId', "No refresh tokens cached for session id: " + sessionId, 401));
			return;
		}

		var refreshToken = sessionIdToRefreshToken[sessionId];

		var options = getLwaPostOptions('/auth/o2/token');
		var reqGrant = 'grant_type=refresh_token' +
			'&refresh_token=' + refreshToken +
			'&client_id=' + config.clientId +
			'&client_secret=' + config.clientSecret;

		var req = https.request(options, function (res) {
			var resultBuffer = null;

			res.on('end', function () {
				if (res.statusCode === 200 && resultBuffer !== null) {
					var result = JSON.parse(resultBuffer);

					// Craft the response to the device
					var reply = {
						access_token: result.access_token,
						expires_in: result.expires_in
					};
					callback(null, reply);
				} else {
					callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
				}
			});

			res.on('data', function (data) {
				if (res.statusCode === 200) {
					if (resultBuffer === null) {
						resultBuffer = data;
					} else {
						resultBuffer = Buffer.concat([resultBuffer, data]);
					}
				} else {
					callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
				}
			});
		});

		req.on('error', function (e) {
			callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', 500));
		});

		req.write(reqGrant);
		req.end();
	};

	/**
	 * Redirects the user to the LWA login page to enter their username and password.
	 *
	 * @param regCode The registration code that was presented to the user and maps their request to the device that generated the registration code.
	 * @param res The HTTP response object.
	 * @param callback The callback(err, json) to return data to the user.
	 */
	auth.register = function (regCode, res, callback) {
		if (regCode.length != REG_NUM_BYTES*2 || !(regCode in regCodeToSessionId)) {
			callback(error('InvalidRegistrationCode', 'The provided registration code was invalid.', 401));
			return;
		} else {
			var sessionId = regCodeToSessionId[regCode];
			var prodInfo = sessionIdToDeviceInfo[sessionId];
			redirectToDeviceAuthenticate(prodInfo, regCode, res);
		}
	};

	/**
	 * Performs the initial request for refreshToken after the user has logged in and redirected to /authresponse.
	 *
	 * @param authCode The authorization code that was included in the redirect from LWA.
	 * @param stateCode The state code that we use to map a redirect from LWA back to device information.
	 * @param callback The callback(err, json) to return data to the user.
	 */
	auth.authresponse = function (authCode, stateCode, callback) {
		var missingProperties = [];
		if (!authCode) {
			missingProperties.push("code");
		}

		if (!stateCode) {
			missingProperties.push("state");
		}

		if (missingProperties.length > 0) {
			callback(error("MissingParams", "The following parameters were missing or empty strings: " + missingProperties.join(", "), 400));
			return;
		}

		if (!(stateCode in pendingStateToRegCode) || !UUID_REGEX.test(stateCode)) {
			callback(error('InvalidStateCode', 'The provided state code was invalid.', 401));
			return;
		}

		var regCode = pendingStateToRegCode[stateCode];
		var sessionId = regCodeToSessionId[regCode];

		var options = getLwaPostOptions('/auth/o2/token');
		var reqGrant = 'grant_type=authorization_code' +
			'&code=' + authCode +
			'&redirect_uri=' + config.redirectUrl +
			'&client_id=' + config.clientId +
			'&client_secret=' + config.clientSecret;

		var req = https.request(options, function (res) {
			var resultBuffer = null;

			res.on('end', function () {
				if (res.statusCode === 200 && resultBuffer !== null) {
					var result = JSON.parse(resultBuffer);

					sessionIdToRefreshToken[sessionId] = result.refresh_token;
					callback(null, "device tokens ready");
				} else {
					callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
				}
			});

			res.on('data', function (data) {
				if (res.statusCode === 200) {
					if (resultBuffer === null) {
						resultBuffer = data;
					} else {
						resultBuffer = Buffer.concat([resultBuffer, data]);
					}
				} else {
					callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
				}
			});
		});

		req.on('error', function (e) {
			console.error('Failed to post request: ' + e.message);
		});

		req.write(reqGrant);
		req.end();
	};

	module.exports = auth;
EOF
	# -------
	cd ~/Desktop/alexa-avs-sample-app
	cd samples/javaclient/src/main/java/com/amazon/alexa/avs/

	rm AVSApp.java

	cat << "EOF" | tee AVSApp.java
	/** 
	 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
	 *
	 * Licensed under the Amazon Software License (the "License"). You may not use this file 
	 * except in compliance with the License. A copy of the License is located at
	 *
	 *   http://aws.amazon.com/asl/
	 *
	 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, 
	 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the 
	 * specific language governing permissions and limitations under the License.
	 */
	package com.amazon.alexa.avs;

	import java.awt.Component;
	import java.awt.Container;
	//import java.awt.Desktop;
	import java.awt.Desktop.Action;
	import java.awt.Dimension;
	import java.awt.FlowLayout;
	import java.awt.Font;
	import java.awt.GridLayout;
	import java.awt.Toolkit;
	import java.awt.datatransfer.Clipboard;
	import java.awt.datatransfer.StringSelection;
	import java.awt.event.ActionEvent;
	import java.awt.event.ActionListener;
	import java.io.IOException;
	import java.io.InputStream;
	//import java.net.URI;
	import java.util.Locale;
	import java.util.Properties;

	import javax.swing.Box;
	import javax.swing.JButton;
	import javax.swing.JComboBox;
	import javax.swing.JFrame;
	import javax.swing.JLabel;
	import javax.swing.JOptionPane;
	import javax.swing.JPanel;
	import javax.swing.JProgressBar;
	import javax.swing.JTextArea;
	import javax.swing.JTextField;
	import javax.swing.SwingWorker;

	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;

	import com.amazon.alexa.avs.auth.AccessTokenListener;
	import com.amazon.alexa.avs.auth.AuthSetup;
	import com.amazon.alexa.avs.auth.companionservice.RegCodeDisplayHandler;
	import com.amazon.alexa.avs.config.DeviceConfig;
	import com.amazon.alexa.avs.config.DeviceConfigUtils;
	import com.amazon.alexa.avs.http.AVSClientFactory;
	import com.amazon.alexa.avs.wakeword.WakeWordDetectedHandler;
	import com.amazon.alexa.avs.wakeword.WakeWordIPCFactory;

	@SuppressWarnings("serial")
	public class AVSApp extends JFrame
			implements ExpectSpeechListener, RecordingRMSListener, RegCodeDisplayHandler,
			AccessTokenListener, ExpectStopCaptureListener, WakeWordDetectedHandler {

		private static final Logger log = LoggerFactory.getLogger(AVSApp.class);

		private static final String APP_TITLE = "Alexa Voice Service";
		private static final String LISTEN_LABEL = "Listen";
		private static final String PROCESSING_LABEL = "Processing";
		private static final String PREVIOUS_LABEL = "\u21E4";
		private static final String NEXT_LABEL = "\u21E5";
		private static final String PAUSE_LABEL = "\u275A\u275A";
		private static final String PLAY_LABEL = "\u25B6";
		private final AVSController controller;
		private JButton actionButton;
		private JButton playPauseButton;
		private Container playbackPanel;
		private JTextField tokenTextField;
		private JProgressBar visualizer;
		private final DeviceConfig deviceConfig;

		private String accessToken;

		private AuthSetup authSetup;

		private enum ButtonState {
			START,
			STOP,
			PROCESSING;
		}

		private ButtonState buttonState;

		public static void main(String[] args) throws Exception {
			if (args.length == 1) {
				new AVSApp(args[0]);
			} else {
				new AVSApp();
			}
		}

		public AVSApp() throws Exception {
			this(DeviceConfigUtils.readConfigFile());
		}

		public AVSApp(String configName) throws Exception {
			this(DeviceConfigUtils.readConfigFile(configName));
		}

		private AVSApp(DeviceConfig config) throws Exception {
			deviceConfig = config;

			controller =
					new AVSController(this, new AVSAudioPlayerFactory(), new AlertManagerFactory(),
							getAVSClientFactory(deviceConfig), DialogRequestIdAuthority.getInstance(),
							new WakeWordIPCFactory(), deviceConfig, this);

			authSetup = new AuthSetup(config, this);
			authSetup.addAccessTokenListener(this);
			authSetup.addAccessTokenListener(controller);
			authSetup.startProvisioningThread();

			addTopPanel();
			addLocaleSelector();
			addTokenField();
			addVisualizerField();
			addActionField();
			addPlaybackButtons();

			getContentPane().setLayout(new GridLayout(0, 1));
			setTitle(getAppTitle());
			setDefaultCloseOperation(EXIT_ON_CLOSE);
			setSize(400, 230);
			setVisible(true);
			controller.initializeStopCaptureHandler(this);
			controller.startHandlingDirectives();
		}

		private String getAppVersion() {
			final Properties properties = new Properties();
			try (final InputStream stream = getClass().getResourceAsStream("/res/version.properties")) {
				properties.load(stream);
				if (properties.containsKey("version")) {
					return properties.getProperty("version");
				}
			} catch (IOException e) {
				log.warn("version.properties file not found on classpath");
			}
			return null;
		}

		private String getAppTitle() {
			String version = getAppVersion();
			String title = APP_TITLE;
			if (version != null) {
				title += " - v" + version;
			}
			return title;
		}

		protected AVSClientFactory getAVSClientFactory(DeviceConfig config) {
			return new AVSClientFactory(config);
		}

		private void addTopPanel() {
			FlowLayout flowLayout = new FlowLayout(FlowLayout.LEFT);
			flowLayout.setHgap(0);
			JPanel topPanel = new JPanel(flowLayout);
			addDeviceField(topPanel);
			getContentPane().add(topPanel);
		}

		private void addDeviceField(JPanel devicePanel) {
			JLabel productIdLabel = new JLabel(deviceConfig.getProductId());
			JLabel dsnLabel = new JLabel(deviceConfig.getDsn());
			productIdLabel.setFont(productIdLabel.getFont().deriveFont(Font.PLAIN));
			dsnLabel.setFont(dsnLabel.getFont().deriveFont(Font.PLAIN));

			devicePanel.add(new JLabel("Device: "));
			devicePanel.add(productIdLabel);
			devicePanel.add(Box.createRigidArea(new Dimension(15, 0)));
			devicePanel.add(new JLabel("DSN: "));
			devicePanel.add(dsnLabel);
			devicePanel.add(Box.createRigidArea(new Dimension(15, 0)));
		}

		private void addLocaleSelector() {
			JPanel localePanel = new JPanel();
			FlowLayout layout = new FlowLayout(FlowLayout.LEFT, 0, 0);
			localePanel.setLayout(layout);
			JLabel localeLabel = new JLabel("Locale: ");
			localePanel.add(localeLabel);
			Object[] locales = DeviceConfig.SUPPORTED_LOCALES.toArray();
			JComboBox<Object> localeSelector = new JComboBox<>(locales);
			localeSelector.setSelectedItem(deviceConfig.getLocale());
			localeSelector.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					Locale locale = (Locale) localeSelector.getSelectedItem();
					deviceConfig.setLocale(locale);
					DeviceConfigUtils.updateConfigFile(deviceConfig);
					controller.setLocale(locale);
				}
			});
			localePanel.add(localeSelector);
			getContentPane().add(localePanel);
		}

		private void addTokenField() {
			getContentPane().add(new JLabel("Bearer Token:"));
			tokenTextField = new JTextField(50);
			tokenTextField.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					controller.onUserActivity();
					authSetup.onAccessTokenReceived(tokenTextField.getText());
				}
			});
			getContentPane().add(tokenTextField);

			if (accessToken != null) {
				tokenTextField.setText(accessToken);
				accessToken = null;
			}
		}

		private void addVisualizerField() {
			visualizer = new JProgressBar(0, 100);
			getContentPane().add(visualizer);
		}

		private void addActionField() {
			final RecordingRMSListener rmsListener = this;
			actionButton = new JButton(LISTEN_LABEL);
			buttonState = ButtonState.START;
			actionButton.setEnabled(true);
			actionButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					controller.onUserActivity();

					if (buttonState == ButtonState.START) { // if in idle mode
						buttonState = ButtonState.STOP;
						setPlaybackControlEnabled(false);

						RequestListener requestListener = new RequestListener() {

							@Override
							public void onRequestSuccess() {
								// In case we get a response from the server without
								// terminating the stream ourselves.
								if (buttonState == ButtonState.STOP) {
									actionButton.doClick();
								}
								finishProcessing();
							}

							@Override
							public void onRequestError(Throwable e) {
								log.error("An error occured creating speech request", e);
								JOptionPane.showMessageDialog(getContentPane(), e.getMessage(), "Error",
										JOptionPane.ERROR_MESSAGE);
								actionButton.doClick();
								finishProcessing();
							}
						};
						controller.startRecording(rmsListener, requestListener);
					} else { // else we must already be in listening
						actionButton.setText(PROCESSING_LABEL); // go into processing mode
						actionButton.setEnabled(false);
						visualizer.setIndeterminate(true);
						buttonState = ButtonState.PROCESSING;
						controller.stopRecording(); // stop the recording so the request can complete
					}
				}
			});

			getContentPane().add(actionButton);
		}

		/**
		 * Respond to a music button press event
		 *
		 * @param action
		 *            Playback action to handle
		 */
		private void musicButtonPressedEventHandler(final PlaybackAction action) {
			SwingWorker<Void, Void> alexaCall = new SwingWorker<Void, Void>() {
				@Override
				public Void doInBackground() throws Exception {
					visualizer.setIndeterminate(true);
					controller.handlePlaybackAction(action);
					return null;
				}

				@Override
				public void done() {
					visualizer.setIndeterminate(false);
				}
			};
			alexaCall.execute();
		}

		private void createMusicButton(Container container, String label, final PlaybackAction action) {
			JButton button = new JButton(label);
			button.setEnabled(true);
			button.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					controller.onUserActivity();
					musicButtonPressedEventHandler(action);
				}
			});
			container.add(button);
		}

		private void setPlaybackControlEnabled(boolean enable) {
			setComponentsOfContainerEnabled(playbackPanel, enable);
		}

		/**
		 * Recursively Enable/Disable components in a container
		 *
		 * @param container
		 *            Object of type Container (like JPanel).
		 * @param enable
		 *            Set true to enable all components in the container. Set to false to disable all.
		 */
		private void setComponentsOfContainerEnabled(Container container, boolean enable) {
			for (Component component : container.getComponents()) {
				if (component instanceof Container) {
					setComponentsOfContainerEnabled((Container) component, enable);
				}
				component.setEnabled(enable);
			}
		}

		/**
		 * Add music control buttons
		 */
		private void addPlaybackButtons() {
			playbackPanel = new JPanel();
			playbackPanel.setLayout(new GridLayout(1, 5));

			playPauseButton = new JButton(PLAY_LABEL + "/" + PAUSE_LABEL);
			playPauseButton.setEnabled(true);
			playPauseButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {

					controller.onUserActivity();
					if (controller.isPlaying()) {
						musicButtonPressedEventHandler(PlaybackAction.PAUSE);
					} else {
						musicButtonPressedEventHandler(PlaybackAction.PLAY);
					}
				}
			});

			createMusicButton(playbackPanel, PREVIOUS_LABEL, PlaybackAction.PREVIOUS);
			playbackPanel.add(playPauseButton);

			createMusicButton(playbackPanel, NEXT_LABEL, PlaybackAction.NEXT);
			getContentPane().add(playbackPanel);
		}

		public void finishProcessing() {
			actionButton.setText(LISTEN_LABEL);
			setPlaybackControlEnabled(true);
			buttonState = ButtonState.START;
			actionButton.setEnabled(true);
			visualizer.setIndeterminate(false);
			controller.processingFinished();
		}

		@Override
		public void rmsChanged(int rms) { // AudioRMSListener callback
			visualizer.setValue(rms); // update the visualizer
		}

		@Override
		public void onExpectSpeechDirective() {
			Thread thread = new Thread() {
				@Override
				public void run() {
					while (!actionButton.isEnabled() || buttonState != ButtonState.START
							|| controller.isSpeaking()) {
						try {
							Thread.sleep(500);
						} catch (Exception e) {
						}
					}
					actionButton.doClick();
				}
			};
			thread.start();
		}

		@Override
		public void onStopCaptureDirective() {
			if (buttonState == ButtonState.STOP) {
				actionButton.doClick();
			}
		}

		public int showYesNoDialog(String message, String title) {
			JTextArea textMessage = new JTextArea(message);
			textMessage.setEditable(false);
			return JOptionPane.showConfirmDialog(getContentPane(), textMessage, title,
					JOptionPane.YES_NO_OPTION);
		}

		public void showDialog(String message, String title) {
			JTextArea textMessage = new JTextArea(message);
			textMessage.setEditable(false);
			JOptionPane.showMessageDialog(getContentPane(), textMessage, title,
					JOptionPane.INFORMATION_MESSAGE);
		}

		@Override
		public void displayRegCode(String regCode) {
			/*
			String title = "Login to Register/Authenticate your Device";
			String regUrl =
					deviceConfig.getCompanionServiceInfo().getServiceUrl() + "/provision/" + regCode;
			if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Action.BROWSE)) {
				int selected = showYesNoDialog(
						"Please register your device by visiting the following URL in "
								+ "a web browser and follow the instructions:\n" + regUrl
								+ "\n\n Would you like to open the URL automatically in your default browser?",
						title);
				if (selected == JOptionPane.YES_OPTION) {
					try {
						Desktop.getDesktop().browse(new URI(regUrl));
					} catch (Exception e) {
						// Ignore and proceed
					}
					title = "Click OK after Registering/Authenticating Device";
					showDialog(
							"If a browser window did not open, please copy and paste the below URL into a "
									+ "web browser, and follow the instructions:\n" + regUrl
									+ "\n\n Click the OK button when finished.",
							title);
				} else {
					handleAuthenticationCopyToClipboard(title, regUrl);
				}
			} else {
				handleAuthenticationCopyToClipboard(title, regUrl);
			}*/
		}

		private void handleAuthenticationCopyToClipboard(String title, String regUrl) {
			int selected =
					showYesNoDialog("Please register your device by visiting the following URL in "
							+ "a web browser and follow the instructions:\n" + regUrl
							+ "\n\n Would you like the URL copied to your clipboard?", title);
			if (selected == JOptionPane.YES_OPTION) {
				copyToClipboard(regUrl);
			}
			showDialog("Click the OK button once you've authenticated with AVS", title);
		}

		private void copyToClipboard(String text) {
			Toolkit defaultToolkit = Toolkit.getDefaultToolkit();
			Clipboard systemClipboard = defaultToolkit.getSystemClipboard();
			systemClipboard.setContents(new StringSelection(text), null);
		}

		@Override
		public synchronized void onAccessTokenReceived(String accessToken) {
			if (tokenTextField == null) {
				this.accessToken = accessToken;
			} else {
				tokenTextField.setText(accessToken);
			}
		}

		@Override
		public synchronized void onWakeWordDetected() {
			if (buttonState == ButtonState.START) { // if in idle mode
				log.info("Wake Word was detected");
				actionButton.doClick();
			}
		}
	}
EOF

	# -------
	cd ~/Desktop/alexa-avs-sample-app
	cd samples/javaclient/src/main/java/com/amazon/alexa/avs/auth/companionservice/

	rm CompanionServiceAuthManager.java 
	cat << "EOF"| tee CompanionServiceAuthManager.java
	/** 
	 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
	 *
	 * Licensed under the Amazon Software License (the "License"). You may not use this file 
	 * except in compliance with the License. A copy of the License is located at
	 *
	 *   http://aws.amazon.com/asl/
	 *
	 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, 
	 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the 
	 * specific language governing permissions and limitations under the License.
	 */
	package com.amazon.alexa.avs.auth.companionservice;

	import com.amazon.alexa.avs.auth.AccessTokenListener;
	import com.amazon.alexa.avs.auth.OAuth2AccessToken;
	import com.amazon.alexa.avs.auth.companionservice.CompanionServiceClient.RemoteServiceException;
	import com.amazon.alexa.avs.config.DeviceConfig;
	import com.amazon.alexa.avs.config.DeviceConfig.CompanionServiceInformation;

	import java.io.IOException;
	import java.util.Date;
	import java.util.Timer;
	import java.util.TimerTask;

	public class CompanionServiceAuthManager {
		/**
		 * How long in seconds before trying again to exchange refreshToken for an accessToken.
		 */
		private static final int TOKEN_REFRESH_RETRY_INTERVAL_IN_S = 2;

		private final DeviceConfig deviceConfig;

		private final CompanionServiceClient companionServiceClient;

		private final RegCodeDisplayHandler regCodeDisplayHandler;

		private final AccessTokenListener accessTokenListener;

		private final Timer refreshTimer;

		private OAuth2AccessToken token;

		public CompanionServiceAuthManager(DeviceConfig deviceConfig,
				CompanionServiceClient remoteProvisioningClient,
				RegCodeDisplayHandler regCodeDisplayHandler, AccessTokenListener accessTokenListener) {
			this.deviceConfig = deviceConfig;
			this.companionServiceClient = remoteProvisioningClient;
			this.regCodeDisplayHandler = regCodeDisplayHandler;
			this.accessTokenListener = accessTokenListener;
			this.refreshTimer = new Timer();
		}

		public void startRemoteProvisioning() {
			if (deviceConfig.getCompanionServiceInfo() != null
					&& deviceConfig.getCompanionServiceInfo().getSessionId() != null) {
				try {
					refreshTokens();
				} catch (RemoteServiceException e) {
					startNewProvisioningRequest();
				}
			} else {
				startNewProvisioningRequest();
			}
		}

		private void startNewProvisioningRequest() {
			//Request a registration code from the CompanionService
			CompanionServiceRegCodeResponse response = requestRegistrationCode();
			//requestAccessToken(response.getSessionId());
			//Invoke the registration procedures on the CompanionService
			try {
				companionServiceClient.callProvisioningWithRegCode(response.getRegCode());
			} catch (IOException e) {
				e.printStackTrace();
			}

			//Loop on trying to request an access token.
			boolean isAccessTokenReady=false;
			while(!isAccessTokenReady){
				try {
					//This will throw until the device is authorized.
					requestAccessToken(response.getSessionId());
					isAccessTokenReady = true;
				} catch (RemoteServiceException e){
					//We catch here because until the CompanionService finishes authorizing the device, the sessionId will be invalid
					try {
						Thread.sleep(1_000);
					} catch (InterruptedException ie) {
					}
				}
			}

		}

		public CompanionServiceRegCodeResponse requestRegistrationCode() {
			while (true) {
				try {
					CompanionServiceRegCodeResponse regCodeResponse =
							companionServiceClient.getRegistrationCode();

					String regCode = regCodeResponse.getRegCode();

					regCodeDisplayHandler.displayRegCode(regCode);
					return regCodeResponse;
				} catch (IOException e) {
					try {
						System.err
								.println("There was a problem connecting to the Companion Service. Trying again in "
										+ TOKEN_REFRESH_RETRY_INTERVAL_IN_S
										+ " seconds. Please make sure it is up and running.");
						Thread.sleep(TOKEN_REFRESH_RETRY_INTERVAL_IN_S * 1000);
					} catch (InterruptedException ie) {
					}
				}
			}
		}

		public void requestAccessToken(String sessionId) {
			if (deviceConfig.getCompanionServiceInfo() != null) {
				while (true) {
					try {
						token = companionServiceClient.getAccessToken(sessionId);

						CompanionServiceInformation info = deviceConfig.getCompanionServiceInfo();
						info.setSessionId(sessionId);
						deviceConfig.saveConfig();

						refreshTimer.schedule(new RefreshTokenTimerTask(),
								new Date(token.getExpiresTime()));

						accessTokenListener.onAccessTokenReceived(token.getAccessToken());
						break;
					} catch (IOException e) {
						try {
							System.err
									.println("There was a problem connecting to the Companion Service. Trying again in "
											+ TOKEN_REFRESH_RETRY_INTERVAL_IN_S
											+ " seconds. Please make sure it is up and running.");
							Thread.sleep(TOKEN_REFRESH_RETRY_INTERVAL_IN_S * 1000);
						} catch (InterruptedException ie) {
						}
					}
				}
			}
		}

		private void refreshTokens() {
			if (deviceConfig.getCompanionServiceInfo() != null) {
				requestAccessToken(deviceConfig.getCompanionServiceInfo().getSessionId());
			}
		}

		/**
		 * TimerTask for refreshing accessTokens every hour.
		 */
		private class RefreshTokenTimerTask extends TimerTask {
			@Override
			public void run() {
				refreshTokens();
			}
		}
	}
EOF

	# -------
	cd ~/Desktop/alexa-avs-sample-app
	cd samples/javaclient/src/main/java/com/amazon/alexa/avs/auth/companionservice/

	rm CompanionServiceClient.java
	cat << "EOF" | tee CompanionServiceClient.java
	/** 
	 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
	 *
	 * Licensed under the Amazon Software License (the "License"). You may not use this file 
	 * except in compliance with the License. A copy of the License is located at
	 *
	 *   http://aws.amazon.com/asl/
	 *
	 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, 
	 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the 
	 * specific language governing permissions and limitations under the License.
	 */
	package com.amazon.alexa.avs.auth.companionservice;

	import com.amazon.alexa.avs.auth.AuthConstants;
	import com.amazon.alexa.avs.auth.OAuth2AccessToken;
	import com.amazon.alexa.avs.auth.companionapp.CompanionAppProvisioningInfo;
	import com.amazon.alexa.avs.config.DeviceConfig;

	import org.apache.commons.io.IOUtils;
	import org.apache.commons.lang3.StringUtils;
	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;

	import java.io.ByteArrayInputStream;
	import java.io.FileInputStream;
	import java.io.IOException;
	import java.io.InputStream;
	import java.io.UnsupportedEncodingException;
	import java.net.HttpURLConnection;
	import java.net.URL;
	import java.net.URLEncoder;
	import java.nio.charset.StandardCharsets;
	import java.security.KeyManagementException;
	import java.security.KeyStore;
	import java.security.KeyStoreException;
	import java.security.NoSuchAlgorithmException;
	import java.security.UnrecoverableKeyException;
	import java.security.cert.Certificate;
	import java.security.cert.CertificateException;
	import java.security.cert.CertificateFactory;
	import java.util.HashMap;
	import java.util.Map;

	import javax.json.Json;
	import javax.json.JsonObject;
	import javax.json.JsonReader;
	import javax.net.ssl.HttpsURLConnection;
	import javax.net.ssl.KeyManagerFactory;
	import javax.net.ssl.SSLContext;
	import javax.net.ssl.SSLSocketFactory;
	import javax.net.ssl.TrustManagerFactory;

	/**
	 * Client for communicating with the companion service and exchanging information for provisioning.
	 */
	public class CompanionServiceClient {

		private final DeviceConfig deviceConfig;
		private SSLSocketFactory pinnedSSLSocketFactory;

		private static final Logger log = LoggerFactory.getLogger(CompanionServiceClient.class);

		/**
		 * Creates an {@link CompanionServiceClient} object.
		 *
		 * @param deviceConfig
		 */
		public CompanionServiceClient(DeviceConfig deviceConfig) {
			this.deviceConfig = deviceConfig;
			this.pinnedSSLSocketFactory = getPinnedSSLSocketFactory();
		}

		/**
		 * Creates an {@link CompanionServiceClient} object.
		 *
		 * @param deviceConfig
		 * @param sslSocketFactory
		 */
		protected CompanionServiceClient(DeviceConfig deviceConfig, SSLSocketFactory sslSocketFactory) {
			this.deviceConfig = deviceConfig;
			this.pinnedSSLSocketFactory = sslSocketFactory;
		}

		/**
		 * Loads the CA certificate into an in-memory keystore and creates an {@link SSLSocketFactory}.
		 *
		 * @return SSLSocketFactory
		 */
		public SSLSocketFactory getPinnedSSLSocketFactory() {
			InputStream caCertInputStream = null;
			InputStream clientKeyPair = null;
			try {
				// Load the CA certificate into memory
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				caCertInputStream =
						new FileInputStream(deviceConfig.getCompanionServiceInfo().getSslCaCert());
				Certificate caCert = cf.generateCertificate(caCertInputStream);

				// Load the CA certificate into the trusted KeyStore
				KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
				trustStore.load(null, null);
				trustStore.setCertificateEntry("myca", caCert);

				// Create a TrustManagerFactory with the trusted KeyStore
				TrustManagerFactory trustManagerFactory =
						TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				trustManagerFactory.init(trustStore);

				// Load the client certificate and private key into another KeyStore
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				clientKeyPair = new FileInputStream(
						deviceConfig.getCompanionServiceInfo().getSslClientKeyStore());
				keyStore.load(clientKeyPair, deviceConfig
						.getCompanionServiceInfo()
						.getSslClientKeyStorePassphrase()
						.toCharArray());

				// Create a TrustManagerFactory with the client key pair KeyStore
				KeyManagerFactory keyManagerFactory =
						KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				keyManagerFactory.init(keyStore, deviceConfig
						.getCompanionServiceInfo()
						.getSslClientKeyStorePassphrase()
						.toCharArray());

				// Initialize the SSLContext and return an SSLSocketFactory;
				SSLContext sc = SSLContext.getInstance("TLS");
				sc.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),
						null);

				return sc.getSocketFactory();
			} catch (CertificateException | KeyStoreException | UnrecoverableKeyException
					| NoSuchAlgorithmException | IOException | KeyManagementException e) {
				throw new RuntimeException(
						"The KeyStore for contacting the Companion Service could not be loaded.", e);
			} finally {
				IOUtils.closeQuietly(caCertInputStream);
				IOUtils.closeQuietly(clientKeyPair);
			}
		}

		/**
		 * Send the device's provisioning information to the companion service, and receive back
		 * {@link CompanionServiceRegCodeResponse} which has a regCode to display to the user.
		 *
		 * @return Information from the companion service to begin the provisioning process.
		 * @throws IOException
		 *             If an I/O exception occurs.
		 */
		public CompanionServiceRegCodeResponse getRegistrationCode() throws IOException {
			Map<String, String> queryParameters = new HashMap<String, String>();
			queryParameters.put(AuthConstants.PRODUCT_ID, deviceConfig.getProductId());
			queryParameters.put(AuthConstants.DSN, deviceConfig.getDsn());

			JsonObject response = callService("/provision/regCode", queryParameters);

			// The sessionId created from the 3pService
			String sessionId = response.getString(AuthConstants.SESSION_ID, null);
			String regCode = response.getString(AuthConstants.REG_CODE, null);

			return new CompanionServiceRegCodeResponse(sessionId, regCode);
		}

		/**
		 * Request the companion service's information once the user has registered. Once the user has
		 * registered and we've received the {@link CompanionAppProvisioningInfo} we can then exchange
		 * that information for tokens.
		 *
		 * @param sessionId
		 * @return accessToken
		 * @throws IOException
		 *             If an I/O exception occurs.
		 */
		public OAuth2AccessToken getAccessToken(String sessionId) throws IOException {
			Map<String, String> queryParameters = new HashMap<String, String>();
			queryParameters.put(AuthConstants.SESSION_ID, sessionId);

			JsonObject response = callService("/provision/accessToken", queryParameters);

			String accessToken = response.getString(AuthConstants.OAuth2.ACCESS_TOKEN, null);
			int expiresIn = response.getInt(AuthConstants.OAuth2.EXPIRES_IN, -1);

			return new OAuth2AccessToken(accessToken, expiresIn);
		}

		JsonObject callService(String path, Map<String, String> parameters) throws IOException {
			HttpURLConnection con = null;
			InputStream response = null;
			try {
				String queryString = mapToQueryString(parameters);
				URL obj = new URL(deviceConfig.getCompanionServiceInfo().getServiceUrl(),
						path + queryString);
				con = (HttpURLConnection) obj.openConnection();

				if (con instanceof HttpsURLConnection) {
					((HttpsURLConnection) con).setSSLSocketFactory(pinnedSSLSocketFactory);
				}

				con.setRequestProperty("Content-Type", "application/json");
				con.setRequestMethod("GET");

				if ((con.getResponseCode() >= 200) || (con.getResponseCode() < 300)) {
					response = con.getInputStream();
				}

				//if (response != null) {
				if (response != null && response.available() != 0) {
					String responsestring = IOUtils.toString(response);
					JsonReader reader = Json
							//.createReader(new ByteArrayInputStream(responsestring.getBytes(StandardCharsets.UTF_8)));
							.createReader(
									new ByteArrayInputStream(
											responsestring.getBytes(StandardCharsets.UTF_8)));
					IOUtils.closeQuietly(response);
					return reader.readObject();
				}
				return Json.createObjectBuilder().build();
			} catch (IOException e) {
				if (con != null) {
					response = con.getErrorStream();

					if (response != null) {
						String responsestring = IOUtils.toString(response);
						JsonReader reader = Json.createReader(
								new ByteArrayInputStream(responsestring.getBytes(StandardCharsets.UTF_8)));
						JsonObject error = reader.readObject();

						String errorName = error.getString("error", null);
						String errorMessage = error.getString("message", null);

						if (!StringUtils.isBlank(errorName) && !StringUtils.isBlank(errorMessage)) {
							throw new RemoteServiceException(errorName + ": " + errorMessage);
						}
					}
				}
				throw e;
			} finally {
				if (response != null) {
					IOUtils.closeQuietly(response);
				}
			}
		}

		private String mapToQueryString(Map<String, String> parameters)
				throws UnsupportedEncodingException {
			StringBuilder queryBuilder = new StringBuilder();
			if ((parameters != null) && (parameters.size() > 0)) {
				queryBuilder.append("?");
				for (Map.Entry<String, String> entry : parameters.entrySet()) {
					if (queryBuilder.length() > 1) {
						queryBuilder.append("&");
					}
					queryBuilder.append(URLEncoder.encode(entry.getKey().toString(),
							StandardCharsets.UTF_8.name()));
					queryBuilder.append("=");
					queryBuilder.append(URLEncoder.encode(entry.getValue().toString(),
							StandardCharsets.UTF_8.name()));
				}
			}
			return queryBuilder.toString();
		}

		@SuppressWarnings("javadoc")
		public static class RemoteServiceException extends RuntimeException {
			private static final long serialVersionUID = 1L;

			public RemoteServiceException(String s) {
				super(s);
			}
		}
		
		public void callProvisioningWithRegCode(String regCode) throws IOException {
			callService("/provision/"+regCode, null);
		}

	}
EOF

	# Validate and Compile Java Changes
	cd ~/Desktop/alexa-avs-sample-app/samples/javaclient/
	mvn validate && mvn install
	# Including autostart on boot
	sudo sed -i "s_exit 0_'~/Desktop/StartAlexa.sh'\n&_" /etc/rc.local
}

echo "Do you wish to make and AutoStart Alexa?"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) autoAlexa; break;;
        No ) exit;;
    esac
done

echo "Everything Done! To run your Alexa, just execute the file StartAlexa on your Desktop using bash StartAlexa.sh" 
