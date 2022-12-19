
// Copyright (c) Eric van Uum. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/**
 * The "azure-iot-device" node enables you to represent an Azure IoT Device in Node-Red.
 * The node provide connecting a device using connection string and DPS
 * You can use a full connection string, a SAS key and a X.509 attestation
 * 
 * The device node enables D2C, C2D messages, Direct Methods, Desired and Reported properties.
 * You can connect to IoT Edge as a downstream device, IoT Hub and IoT Central.
 */
module.exports = function (RED) {
    'use strict'
    const Client = require('azure-iot-device').Client;
    const Message = require('azure-iot-device').Message;
    const debug = require('debug')("azureiotdevice");

    // Only AMQP(WS) or MQTT(WS) used as protocol, no HTTP support
    const Protocols = {
        amqp: require('azure-iot-device-amqp').Amqp,
        amqpWs: require('azure-iot-device-amqp').AmqpWs,
        mqtt: require('azure-iot-device-mqtt').Mqtt,
        mqttWs: require('azure-iot-device-mqtt').MqttWs
    };

    // Only AMQP(WS) or MQTT(WS) used as protocol, no HTTP support
    const ProvisioningProtocols = {
        amqp: require('azure-iot-provisioning-device-amqp').Amqp,
        amqpWs: require('azure-iot-provisioning-device-amqp').AmqpWs,
        mqtt: require('azure-iot-provisioning-device-mqtt').Mqtt,
        mqttWs: require('azure-iot-provisioning-device-mqtt').MqttWs
    };

    const SecurityClient = {
        x509: require('azure-iot-security-x509').X509Security,
        sas: require('azure-iot-security-symmetric-key').SymmetricKeySecurityClient
    };

    const ProvisioningDeviceClient = require('azure-iot-provisioning-device').ProvisioningDeviceClient;
    const GlobalProvisoningEndpoint = "global.azure-devices-provisioning.net";

    const crypto = require('crypto');
    const forge = require('node-forge');
    var pki = forge.pki;

    const { config } = require('process');

    const statusEnum = {
        connected: { fill: "green", shape: "dot", text: "Connected" },
        connecting: { fill: "blue", shape: "dot", text: "Connecting" },
        provisioning: { fill: "blue", shape: "dot", text: "Provisioning" },
        disconnected: { fill: "red", shape: "dot", text: "Disconnected" },
        error: { fill: "grey", shape: "dot", text: "Error" }
    };

    // Setup node-red node to represent Azure IoT Device
    class AzureIoTDevice {
        constructor(config) {
            // Create the Node-RED node
            RED.nodes.createNode(this, config);

            // Set properties
            this.deviceid = config.deviceid;
            this.pnpModelid = config.pnpModelid;
            this.connectiontype = config.connectiontype;
            this.authenticationmethod = config.authenticationmethod;
            this.enrollmenttype = config.enrollmenttype;
            this.iothub = config.iothub;
            this.isIotcentral = config.isIotcentral;
            this.scopeid = config.scopeid;
            this.saskey = config.saskey;
            this.protocol = config.protocol;
            this.retryInterval = config.retryInterval;
            this.methods = config.methods;
            this.DPSpayload = config.DPSpayload;
            this.gatewayHostname = config.gatewayHostname;
            this.cert = config.cert;
            this.key = config.key;
            this.passphrase = config.passphrase;
            this.ca = config.ca;
            this.maxQueueLength = config.maxQueueLength;
            // Array to hold the direct method responses
            this.methodResponses = [];
            //** @type {device.Client} */ this.client;
            this.client = null;
            //** @type {device.Twin} */ this.twin;
            this.twin = null;
            this.currentStatus = statusEnum.provisioning;


            /** @type {Promise<void>|null} */
            this.sendMessagesPromise = null;


            setStatus(this, statusEnum.disconnected);

            // Initiate
            initiateDevice(this);
        }

        useQueue(func) {
            const queue = this.messageQueue;
            const result = func(queue);
            this.messageQueue = queue;
            return result;
        }

        get messageQueue() {
            const result = this.context().get("messageQueue", "file");
            return result || [];
        }
        set messageQueue(val) {
            const maxQueueLength = parseInt(this.maxQueueLength || 1);
            if (val.length > maxQueueLength) {
                error(this, { queueLength: val.length, maxQueueLength }, "Queue length exceeded, queue has been truncated");
                val = val.slice(0, maxQueueLength);
            }
            this.context().set("messageQueue", val, "file");
        }

        debug(formatter, ...args) {
            debug(`${this.deviceid}: ${formatter}`, ...args);
        }
    };


    // Set status of node on node-red
    var setStatus = function (/**@type {AzureIoTDevice} */ node, status) {
        if (!status) {
            status = node.currentStatus;
        }
        else {
            node.currentStatus = status;
        }
        node.status({
            fill: status.fill,
            shape: status.shape,
            text: status.text + " (" + node.messageQueue.length + " queued)"
        });
    };


    // Send catchable error to node-red
    var error = function (node, payload, message) {
        var msg = {};
        msg.topic = 'error';
        msg.message = message;
        msg.payload = payload;
        node.error(msg);
    }


    var setErrorStatus = function (node, message, err) {
        error(node, err, `${node.deviceId} -> ${message}`);
        setStatus(node, {
            ...statusEnum.error,
            text: `Error: ${message}`
        })
    }

    // Check if valid PEM cert
    function verifyCertificatePem(node, pem) {
        try {
            // Get the certificate from pem, if successful it is a cert
            node.debug('Verifying PEM Certificate');
            var cert = pki.certificateFromPem(pem);
        } catch (err) {
            return false;
        }
        return true;
    };

    // Compute device SAS key
    function computeDerivedSymmetricKey(masterKey, regId) {
        return crypto.createHmac('SHA256', Buffer.from(masterKey, 'base64'))
            .update(regId, 'utf8')
            .digest('base64');
    };

    // Close all listeners
    function closeAll(node) {
        node.debug('Closing all clients.');
        try {
            node.twin.removeAllListeners();
            node.twin = null;
        } catch (err) {
            node.twin = null;
        }
        try {
            node.client.removeAllListeners();
            node.client.close((err, result) => {
                if (err) {
                    node.debug('Azure IoT Device Client close failed: ' + JSON.stringify(err));
                } else {
                    node.debug('Azure IoT Device Client closed.');
                }
            });
            node.client = null;
        } catch (err) {
            node.client = null;
        }
    };

    // Initiate provisioning and retry if network not available.
    async function initiateDevice(node) {

        // Ensure resources are reset
        node.on('close', function (done) {
            closeAll(node);
            done();
        });

        // Listen to node input to send telemetry or reported properties
        node.on('input', function (msg) {
            if (typeof (msg.payload) === "string") {
                //Converting string to JSON Object
                msg.payload = JSON.parse(msg.payload);
            }
            if (msg.topic === 'telemetry') {
                sendDeviceTelemetry(node, msg, msg.properties);
            } else if (msg.topic === 'property' && node.twin) {
                sendDeviceProperties(node, msg);
            } else if (msg.topic === 'response') {
                node.debug('Method response received with id: ' + msg.payload.requestId);
                sendMethodResponse(node, msg)
            } else {
                error(node, msg, node.deviceid + ' -> Incorrect input. Must be of type \"telemetry\" or \"property\" or \"response\".');
            }
        });

        // Provision device
        node.retries = 0;
        try {
            const provisionResult = await provisionDevice(node);
            if (!provisionResult) {
                throw "No Provision result";
            }
            // Connect device to Azure IoT
            node.retries = 0;
            await connectDevice(node, provisionResult);
            await retrieveTwin(node);
            node.debug("initiate device complete")
        }
        catch (err) {
            if (err instanceof string) {
                setErrorStatus(node, `Device provisioning failed: ${err}`, err);
            }
            else {
                setErrorStatus(node, "Device provisioning failed", err);
            }
        }
    };

    // Provision the client 
    function provisionDevice(node) {
        // Set status
        setStatus(node, statusEnum.provisioning);

        // Return a promise to enable retry
        return new Promise((resolve, reject) => {
            try {
                // Log the start
                node.debug('Initiate IoT Device settings.');

                // Set the security properties
                var options = {};
                if (node.authenticationmethod === "x509") {
                    node.debug('Validating device certificates.');
                    // Set cert options
                    // verify PEM work around for SDK issue
                    if (verifyCertificatePem(node, node.cert)) {
                        options = {
                            cert: node.cert,
                            key: node.key,
                            passphrase: node.passphrase
                        };
                    } else {
                        reject("Invalid certificates.");
                    }
                };

                // Check if connection type is dps, if not skip the provisioning step
                if (node.connectiontype === "dps") {

                    // Set provisioning protocol to selected (default to AMQP-WS)
                    var provisioningProtocol = (node.protocol === "amqp") ? ProvisioningProtocols.amqp :
                        (node.protocol === "amqpWs") ? ProvisioningProtocols.amqpWs :
                            (node.protocol === "mqtt") ? ProvisioningProtocols.mqtt :
                                (node.protocol === "mqttWs") ? ProvisioningProtocols.mqttWs :
                                    ProvisioningProtocols.amqpWs;

                    // Set security client based on SAS or X.509
                    var saskey = (node.enrollmenttype === "group") ? computeDerivedSymmetricKey(node.saskey, node.deviceid) : node.saskey;
                    var provisioningSecurityClient =
                        (node.authenticationmethod === "sas") ? new SecurityClient.sas(node.deviceid, saskey) :
                            new SecurityClient.x509(node.deviceid, options);

                    // Create provisioning client
                    var provisioningClient = ProvisioningDeviceClient.create(GlobalProvisoningEndpoint, node.scopeid, new provisioningProtocol(), provisioningSecurityClient);

                    // set the provisioning payload (for custom allocation)
                    var payload = {};
                    if (node.DPSpayload) {
                        // Turn payload into JSON
                        try {
                            payload = JSON.parse(node.DPSpayload);
                            node.debug('DPS Payload added.');
                        } catch (err) {
                            // do nothing 
                        }
                    }

                    // Register the device.
                    node.debug('Provision IoT Device using DPS.');
                    if (node.connectiontype === "constr") {
                        resolve(options);
                    } else {
                        provisioningClient.setProvisioningPayload(JSON.stringify(payload));
                        provisioningClient.register().then(result => {
                            // Process provisioning details
                            node.debug('DPS registration succeeded.');
                            node.debug('Assigned hub: ' + result.assignedHub);
                            var msg = {};
                            msg.topic = 'provisioning';
                            msg.deviceId = result.deviceId;
                            msg.payload = JSON.parse(JSON.stringify(result));
                            node.send(msg);
                            node.iothub = result.assignedHub;
                            node.deviceid = result.deviceId;
                            setStatus(node, statusEnum.disconnected);
                            resolve(options);
                        }).catch(function (err) {
                            // Handle error
                            setErrorStatus(node, "DPS registration failed", err);
                            reject(err);
                        });
                    }
                } else {
                    resolve(options);
                }
            } catch (err) {
                reject("Failed to provision device: " + err);
            }
        });
    }

    // Initiate an IoT device node in node-red
    function connectDevice(node, options) {
        // Set status
        setStatus(node, statusEnum.connecting);

        // Set provisioning protocol to selected (default to AMQP-WS)
        var deviceProtocol = (node.protocol === "amqp") ? Protocols.amqp :
            (node.protocol === "amqpWs") ? Protocols.amqpWs :
                (node.protocol === "mqtt") ? Protocols.mqtt :
                    (node.protocol === "mqttWs") ? Protocols.mqttWs :
                        Protocols.amqpWs;
        // Set the client connection string and options
        var connectionString = 'HostName=' + node.iothub + ';DeviceId=' + node.deviceid;
        // Finalize the connection string
        var saskey = (node.connectiontype === "dps" && node.enrollmenttype === "group" && node.authenticationmethod === 'sas') ? computeDerivedSymmetricKey(node.saskey, node.deviceid) : node.saskey;
        connectionString = connectionString + ((node.authenticationmethod === 'sas') ? (';SharedAccessKey=' + saskey) : ';x509=true');

        // Update options
        if (node.gatewayHostname !== "") {
            node.debug('Connect through gateway: ' + node.gatewayHostname);
            try {
                options.ca = node.ca;
                connectionString = connectionString + ';GatewayHostName=' + node.gatewayHostname;
            } catch (err) {
                setErrorStatus(node, "Certificate file error", err);
            };
        }

        // Define the client
        node.client = Client.fromConnectionString(connectionString, deviceProtocol);

        // Add pnp modelid to options
        if (node.pnpModelid) {
            options.modelId = node.pnpModelid;
            node.debug('Set PnP Model ID: ' + node.pnpModelid);
        }

        // Return the promise
        return new Promise((resolve, reject) => {
            // Set the options first and then open the connection
            node.client.setOptions(options).then(result => {
                node.client.open().then(result => {
                    // Setup the client
                    // React or errors
                    node.client.on('error', function (err) {
                        setErrorStatus(node, "Device Client error", err);
                    });

                    // React on disconnect and try to reconnect
                    node.client.on('disconnect', function (err) {
                        error(node, err, node.deviceid + ' -> Device Client disconnected.');
                        setStatus(node, statusEnum.disconnected);
                        closeAll(node);
                        initiateDevice(node);
                    });

                    // Listen to commands for defined direct methods
                    for (let method in node.methods) {
                        node.debug('Adding synchronous command: ' + node.methods[method].name);
                        var mthd = node.methods[method].name;
                        // Define the method on the client
                        node.client.onDeviceMethod(mthd, function (request, response) {
                            node.debug('Command received: ' + request.methodName);
                            node.debug('Command payload: ' + JSON.stringify(request.payload));
                            node.send({ payload: request, topic: "command", deviceId: node.deviceid });

                            // Now wait for the response
                            getResponse(node, request.requestId).then(message => {
                                var rspns = message.payload;
                                node.debug('Method response status: ' + rspns.status);
                                node.debug('Method response payload: ' + JSON.stringify(rspns.payload));
                                response.send(rspns.status, rspns.payload, function (err) {
                                    if (err) {
                                        node.debug('Failed sending method response: ' + err);
                                    } else {
                                        node.debug('Successfully sent method response: ' + request.methodName);
                                    }
                                });
                            })
                                .catch(function (err) {
                                    error(node, err, node.deviceid + ' -> Failed sending method response: \"' + request.methodName + '\".');
                                });
                        });
                    };

                    // Start listening to C2D messages
                    node.debug('Listening to C2D messages');
                    // Define the message listener
                    node.client.on('message', function (msg) {
                        node.debug('C2D message received, data: ' + msg.data);
                        var message = {
                            messageId: msg.messageId,
                            data: msg.data.toString('utf8'),
                            properties: msg.properties
                        };
                        node.send({ payload: message, topic: "message", deviceId: node.deviceid });
                        node.client.complete(msg, function (err) {
                            if (err) {
                                error(node, err, node.deviceid + ' -> C2D Message complete error.');
                            } else {
                                node.debug('C2D Message completed.');
                            }
                        });
                    });

                    node.debug('Device client connected.');
                    setStatus(node, statusEnum.connected);
                    resolve(null);
                }).catch(function (err) {
                    setErrorStatus(node, "Device client open failed", err);
                    reject(err);
                });
            }).catch(function (err) {
                setErrorStatus(node, "Device options setting failed", err);
                reject(err);
            });

        });
    };

    // Get the device twin 
    function retrieveTwin(node) {
        // Set the options first and then open the connection
        node.debug('Retrieve device twin.');
        return new Promise((resolve, reject) => {
            node.client.getTwin().then(result => {
                node.debug('Device twin created.');
                node.twin = result;
                node.debug('Twin contents');
                // Send the twin properties to Node Red
                var msg = {};
                msg.topic = 'property';
                msg.deviceId = node.deviceid;
                msg.payload = JSON.parse(JSON.stringify(node.twin.properties));
                node.send(msg);

                // Get the desired properties
                node.twin.on('properties.desired', function (payload) {
                    node.debug('Desired properties received');
                    var msg = {};
                    msg.topic = 'property';
                    msg.deviceId = node.deviceid;
                    msg.payload = payload;
                    node.send(msg);
                });
            }).catch(err => {
                error(node, err, node.deviceid + ' -> Device twin retrieve failed.');
                reject(err);
            });
        })
    };

    // Send messages to IoT platform (Transparant Edge, IoT Hub, IoT Central)
    function sendDeviceTelemetry(node, message, properties) {
        if (!validateMessage(message.payload)) {
            error(node, message, node.deviceid + ' -> Invalid telemetry format.');
            return;
        }
        const serialized = {
            payload: JSON.stringify(message.payload),
            properties
        };
        // Send the message
        queueMessage(node, serialized);

    };

    function queueMessage(node, msg) {
        node.useQueue(q => q.push(msg));
        setStatus(node, null);
        startMessageSendingTask(node);
    }

    function startMessageSendingTask(node) {
        if (node.sendMessagesPromise) {
            node?.debug("Message sending task is already running, do not start a new task.")
            return;
        }
        node.sendMessagesPromise = sendQueuedMessagesAsync(node);
    }

    async function sendQueuedMessagesAsync(node) {
        node?.debug("Starting a new message sending task...")
        const maxMessagesPerBatch = 100;
        while (true) {
            const queue = node.messageQueue;
            const messagesToSend = queue.slice(0, maxMessagesPerBatch);
            if (messagesToSend.length === 0) {
                break;
            }
            const remainingMessages = queue.slice(maxMessagesPerBatch);
            node.messageQueue = remainingMessages;
            node?.debug(`Sending ${messagesToSend.length} messages, ${remainingMessages.length} left in queue`);

            const sendPromises = messagesToSend.map(message => sendMessageAsync(node, message));
            const statuses = await Promise.all(sendPromises);

            const failures = statuses.filter(status => status.error !== null);
            if (failures.length > 0) {
                //re-queue failed messages
                node.useQueue(q => q.push(...failures.map(f => f.message)));
                const firstError = failures[0].error.toString();
                setStatus(node, { fill: "yellow", shape: "dot", text: "Err: " + firstError });
                node?.debug(`Tried to send ${messagesToSend.length}, but had ${failures.length} errors: ${firstError}`);
                await timeoutPromise(10_000);
                setStatus(node, { fill: "yellow", shape: "dot", text: "Retrying..." });
            }
            else {
                node?.debug(`Sent ${messagesToSend.length} without problems`);
                setStatus(node, statusEnum.connected);
            }
        }
        node?.debug("Message sending task completed");
        node.sendMessagesPromise = null;
    }

    function sendMessageAsync(node, message) {
        return new Promise((resolve, reject) => {

            if (!node.client) {
                setStatus(node, statusEnum.disconnected);
                resolve({ error: "No node", message });
                return;
            }
            // Create message and set encoding and type
            var msg = new Message(message.payload);
            // Check if properties set and add if so
            if (message.properties) {
                for (let property of message.properties) {
                    msg.properties.add(property.key, property.value);
                }
            }
            msg.contentEncoding = 'utf-8';
            msg.contentType = 'application/json';
            let isResolved = false;
            timeoutPromise(20_000).then(() => {
                if (isResolved)
                    return;
                resolve({ error: "timeout", message })
            })
            node.client.sendEvent(msg, (err, _) => {
                isResolved = true;
                if (err) {
                    node.log("error sending message: " + err);

                    resolve({ error: err.toString(), message });
                }
                else {
                    resolve({ error: null, message });
                }
            });
        });
    }

    function timeoutPromise(timeoutMs) {
        return new Promise(function (resolve, reject) {
            setTimeout(resolve, timeoutMs);
        })
    }


    // Send device reported properties.
    function sendDeviceProperties(node, message) {
        if (node.twin) {
            node.twin.properties.reported.update(message.payload, function (err) {
                if (err) {
                    setErrorStatus(node, "Sending device properties failed", err);
                } else {
                    node.debug('Device properties sent');
                    setStatus(node, statusEnum.connected);
                }
            });
        }
        else {
            error(node, message, node.deviceid + ' -> Unable to send device properties, device not connected.');
        }
    };

    // Send device direct method response.
    function sendMethodResponse(node, message) {
        // Push the reponse to the array
        var methodResponse = message.payload;
        node.debug('Creating response for command: ' + methodResponse.methodName);
        node.methodResponses.push(
            { requestId: methodResponse.requestId, response: message }
        );
    };

    // Get method response using promise, and retry, and slow backoff
    function getResponse(node, requestId) {
        var retries = 20;
        var timeOut = 1000;
        // Retrieve client using progressive promise to wait for method response
        var promise = Promise.reject();
        for (var i = 1; i <= retries; i++) {
            promise = promise.catch(function () {
                var methodResponse = node.methodResponses.find(function (m) { return m.requestId === requestId });
                if (methodResponse) {
                    // get the response and clean the array
                    node.methodResponses.splice(node.methodResponses.findIndex(function (m) { return m.requestId === requestId }), 1);
                    return methodResponse.response;
                }
                else {
                    throw new Error(node.deviceid + ' -> Method Response not received..');
                }
            })
                .catch(function rejectDelay(reason) {
                    return new Promise(function (resolve, reject) {
                        setTimeout(reject.bind(null, reason), timeOut * ((i % 10) + 1));
                    });
                });
        }
        return promise;
    };

    // @returns true if message object is valid, i.e., a map of field names to numbers, strings and booleans.
    function validateMessage(message) {
        if (!message || typeof message !== 'object') {
            return false;
        }
        for (let field in message) {
            if (typeof message[field] !== 'number' && typeof message[field] !== 'string' && typeof message[field] !== 'boolean') {
                if (typeof message[field] === 'object') {
                    validateMessage(message[field]);
                }
                else {
                    return false;
                }
            }
        }
        return true;
    };

    // Registration of the node into Node-RED
    RED.nodes.registerType("azureiotdevice", AzureIoTDevice, {
        defaults: {
            deviceid: { value: "" },
            pnpModelid: { value: "" },
            connectiontype: { value: "" },
            authenticationmethod: { value: "" },
            enrollmenttype: { value: "" },
            iothub: { value: "" },
            isIotcentral: { value: false },
            scopeid: { value: "" },
            saskey: { value: "" },
            certname: { value: "" },
            keyname: { value: "" },
            passphrase: { value: "" },
            protocol: { value: "" },
            retryInterval: { value: 10 },
            methods: { value: [] },
            DPSpayload: { value: "" },
            isDownstream: { value: false },
            gatewayHostname: { value: "" },
            caname: { value: "" },
            cert: { type: "text" },
            key: { type: "text" },
            ca: { type: "text" },
            maxQueueLength: { value: 10_000 }
        }
    });

}
