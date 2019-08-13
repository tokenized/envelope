/**
 * @fileoverview
 * @enhanceable
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!


goog.provide('proto.protobuf.EncryptedPayload');
goog.provide('proto.protobuf.Envelope');
goog.provide('proto.protobuf.MetaNet');
goog.provide('proto.protobuf.Receiver');

goog.require('jspb.Message');
goog.require('jspb.BinaryReader');
goog.require('jspb.BinaryWriter');


/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.protobuf.Envelope = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.protobuf.Envelope.repeatedFields_, null);
};
goog.inherits(proto.protobuf.Envelope, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.protobuf.Envelope.displayName = 'proto.protobuf.Envelope';
}
/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.protobuf.Envelope.repeatedFields_ = [5];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.protobuf.Envelope.prototype.toObject = function(opt_includeInstance) {
  return proto.protobuf.Envelope.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.protobuf.Envelope} msg The msg instance to transform.
 * @return {!Object}
 */
proto.protobuf.Envelope.toObject = function(includeInstance, msg) {
  var f, obj = {
    version: msg.getVersion(),
    type: msg.getType_asB64(),
    identifier: msg.getIdentifier_asB64(),
    metanet: (f = msg.getMetanet()) && proto.protobuf.MetaNet.toObject(includeInstance, f),
    encryptedpayloadsList: jspb.Message.toObjectList(msg.getEncryptedpayloadsList(),
    proto.protobuf.EncryptedPayload.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.protobuf.Envelope}
 */
proto.protobuf.Envelope.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.protobuf.Envelope;
  return proto.protobuf.Envelope.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.protobuf.Envelope} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.protobuf.Envelope}
 */
proto.protobuf.Envelope.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readUint64());
      msg.setVersion(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setType(value);
      break;
    case 3:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setIdentifier(value);
      break;
    case 4:
      var value = new proto.protobuf.MetaNet;
      reader.readMessage(value,proto.protobuf.MetaNet.deserializeBinaryFromReader);
      msg.setMetanet(value);
      break;
    case 5:
      var value = new proto.protobuf.EncryptedPayload;
      reader.readMessage(value,proto.protobuf.EncryptedPayload.deserializeBinaryFromReader);
      msg.getEncryptedpayloadsList().push(value);
      msg.setEncryptedpayloadsList(msg.getEncryptedpayloadsList());
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Class method variant: serializes the given message to binary data
 * (in protobuf wire format), writing to the given BinaryWriter.
 * @param {!proto.protobuf.Envelope} message
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.Envelope.serializeBinaryToWriter = function(message, writer) {
  message.serializeBinaryToWriter(writer);
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.protobuf.Envelope.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  this.serializeBinaryToWriter(writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the message to binary data (in protobuf wire format),
 * writing to the given BinaryWriter.
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.Envelope.prototype.serializeBinaryToWriter = function (writer) {
  var f = undefined;
  f = this.getVersion();
  if (f !== 0) {
    writer.writeUint64(
      1,
      f
    );
  }
  f = this.getType_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
  f = this.getIdentifier_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      3,
      f
    );
  }
  f = this.getMetanet();
  if (f != null) {
    writer.writeMessage(
      4,
      f,
      proto.protobuf.MetaNet.serializeBinaryToWriter
    );
  }
  f = this.getEncryptedpayloadsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      5,
      f,
      proto.protobuf.EncryptedPayload.serializeBinaryToWriter
    );
  }
};


/**
 * Creates a deep clone of this proto. No data is shared with the original.
 * @return {!proto.protobuf.Envelope} The clone.
 */
proto.protobuf.Envelope.prototype.cloneMessage = function() {
  return /** @type {!proto.protobuf.Envelope} */ (jspb.Message.cloneMessage(this));
};


/**
 * optional uint64 Version = 1;
 * @return {number}
 */
proto.protobuf.Envelope.prototype.getVersion = function() {
  return /** @type {number} */ (jspb.Message.getFieldProto3(this, 1, 0));
};


/** @param {number} value  */
proto.protobuf.Envelope.prototype.setVersion = function(value) {
  jspb.Message.setField(this, 1, value);
};


/**
 * optional bytes Type = 2;
 * @return {!(string|Uint8Array)}
 */
proto.protobuf.Envelope.prototype.getType = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldProto3(this, 2, ""));
};


/**
 * optional bytes Type = 2;
 * This is a type-conversion wrapper around `getType()`
 * @return {string}
 */
proto.protobuf.Envelope.prototype.getType_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getType()));
};


/**
 * optional bytes Type = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getType()`
 * @return {!Uint8Array}
 */
proto.protobuf.Envelope.prototype.getType_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getType()));
};


/** @param {!(string|Uint8Array)} value  */
proto.protobuf.Envelope.prototype.setType = function(value) {
  jspb.Message.setField(this, 2, value);
};


/**
 * optional bytes Identifier = 3;
 * @return {!(string|Uint8Array)}
 */
proto.protobuf.Envelope.prototype.getIdentifier = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldProto3(this, 3, ""));
};


/**
 * optional bytes Identifier = 3;
 * This is a type-conversion wrapper around `getIdentifier()`
 * @return {string}
 */
proto.protobuf.Envelope.prototype.getIdentifier_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getIdentifier()));
};


/**
 * optional bytes Identifier = 3;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getIdentifier()`
 * @return {!Uint8Array}
 */
proto.protobuf.Envelope.prototype.getIdentifier_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getIdentifier()));
};


/** @param {!(string|Uint8Array)} value  */
proto.protobuf.Envelope.prototype.setIdentifier = function(value) {
  jspb.Message.setField(this, 3, value);
};


/**
 * optional MetaNet MetaNet = 4;
 * @return {proto.protobuf.MetaNet}
 */
proto.protobuf.Envelope.prototype.getMetanet = function() {
  return /** @type{proto.protobuf.MetaNet} */ (
    jspb.Message.getWrapperField(this, proto.protobuf.MetaNet, 4));
};


/** @param {proto.protobuf.MetaNet|undefined} value  */
proto.protobuf.Envelope.prototype.setMetanet = function(value) {
  jspb.Message.setWrapperField(this, 4, value);
};


proto.protobuf.Envelope.prototype.clearMetanet = function() {
  this.setMetanet(undefined);
};


/**
 * Returns whether this field is set.
 * @return{!boolean}
 */
proto.protobuf.Envelope.prototype.hasMetanet = function() {
  return jspb.Message.getField(this, 4) != null;
};


/**
 * repeated EncryptedPayload EncryptedPayloads = 5;
 * If you change this array by adding, removing or replacing elements, or if you
 * replace the array itself, then you must call the setter to update it.
 * @return {!Array.<!proto.protobuf.EncryptedPayload>}
 */
proto.protobuf.Envelope.prototype.getEncryptedpayloadsList = function() {
  return /** @type{!Array.<!proto.protobuf.EncryptedPayload>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.protobuf.EncryptedPayload, 5));
};


/** @param {Array.<!proto.protobuf.EncryptedPayload>} value  */
proto.protobuf.Envelope.prototype.setEncryptedpayloadsList = function(value) {
  jspb.Message.setRepeatedWrapperField(this, 5, value);
};


proto.protobuf.Envelope.prototype.clearEncryptedpayloadsList = function() {
  this.setEncryptedpayloadsList([]);
};



/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.protobuf.MetaNet = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.protobuf.MetaNet, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.protobuf.MetaNet.displayName = 'proto.protobuf.MetaNet';
}


if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.protobuf.MetaNet.prototype.toObject = function(opt_includeInstance) {
  return proto.protobuf.MetaNet.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.protobuf.MetaNet} msg The msg instance to transform.
 * @return {!Object}
 */
proto.protobuf.MetaNet.toObject = function(includeInstance, msg) {
  var f, obj = {
    index: msg.getIndex(),
    parent: msg.getParent_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.protobuf.MetaNet}
 */
proto.protobuf.MetaNet.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.protobuf.MetaNet;
  return proto.protobuf.MetaNet.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.protobuf.MetaNet} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.protobuf.MetaNet}
 */
proto.protobuf.MetaNet.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setIndex(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setParent(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Class method variant: serializes the given message to binary data
 * (in protobuf wire format), writing to the given BinaryWriter.
 * @param {!proto.protobuf.MetaNet} message
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.MetaNet.serializeBinaryToWriter = function(message, writer) {
  message.serializeBinaryToWriter(writer);
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.protobuf.MetaNet.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  this.serializeBinaryToWriter(writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the message to binary data (in protobuf wire format),
 * writing to the given BinaryWriter.
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.MetaNet.prototype.serializeBinaryToWriter = function (writer) {
  var f = undefined;
  f = this.getIndex();
  if (f !== 0) {
    writer.writeUint32(
      1,
      f
    );
  }
  f = this.getParent_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
};


/**
 * Creates a deep clone of this proto. No data is shared with the original.
 * @return {!proto.protobuf.MetaNet} The clone.
 */
proto.protobuf.MetaNet.prototype.cloneMessage = function() {
  return /** @type {!proto.protobuf.MetaNet} */ (jspb.Message.cloneMessage(this));
};


/**
 * optional uint32 Index = 1;
 * @return {number}
 */
proto.protobuf.MetaNet.prototype.getIndex = function() {
  return /** @type {number} */ (jspb.Message.getFieldProto3(this, 1, 0));
};


/** @param {number} value  */
proto.protobuf.MetaNet.prototype.setIndex = function(value) {
  jspb.Message.setField(this, 1, value);
};


/**
 * optional bytes Parent = 2;
 * @return {!(string|Uint8Array)}
 */
proto.protobuf.MetaNet.prototype.getParent = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldProto3(this, 2, ""));
};


/**
 * optional bytes Parent = 2;
 * This is a type-conversion wrapper around `getParent()`
 * @return {string}
 */
proto.protobuf.MetaNet.prototype.getParent_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getParent()));
};


/**
 * optional bytes Parent = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getParent()`
 * @return {!Uint8Array}
 */
proto.protobuf.MetaNet.prototype.getParent_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getParent()));
};


/** @param {!(string|Uint8Array)} value  */
proto.protobuf.MetaNet.prototype.setParent = function(value) {
  jspb.Message.setField(this, 2, value);
};



/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.protobuf.EncryptedPayload = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.protobuf.EncryptedPayload.repeatedFields_, null);
};
goog.inherits(proto.protobuf.EncryptedPayload, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.protobuf.EncryptedPayload.displayName = 'proto.protobuf.EncryptedPayload';
}
/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.protobuf.EncryptedPayload.repeatedFields_ = [2];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.protobuf.EncryptedPayload.prototype.toObject = function(opt_includeInstance) {
  return proto.protobuf.EncryptedPayload.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.protobuf.EncryptedPayload} msg The msg instance to transform.
 * @return {!Object}
 */
proto.protobuf.EncryptedPayload.toObject = function(includeInstance, msg) {
  var f, obj = {
    sender: msg.getSender(),
    receiversList: jspb.Message.toObjectList(msg.getReceiversList(),
    proto.protobuf.Receiver.toObject, includeInstance),
    payload: msg.getPayload_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.protobuf.EncryptedPayload}
 */
proto.protobuf.EncryptedPayload.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.protobuf.EncryptedPayload;
  return proto.protobuf.EncryptedPayload.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.protobuf.EncryptedPayload} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.protobuf.EncryptedPayload}
 */
proto.protobuf.EncryptedPayload.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setSender(value);
      break;
    case 2:
      var value = new proto.protobuf.Receiver;
      reader.readMessage(value,proto.protobuf.Receiver.deserializeBinaryFromReader);
      msg.getReceiversList().push(value);
      msg.setReceiversList(msg.getReceiversList());
      break;
    case 3:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setPayload(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Class method variant: serializes the given message to binary data
 * (in protobuf wire format), writing to the given BinaryWriter.
 * @param {!proto.protobuf.EncryptedPayload} message
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.EncryptedPayload.serializeBinaryToWriter = function(message, writer) {
  message.serializeBinaryToWriter(writer);
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.protobuf.EncryptedPayload.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  this.serializeBinaryToWriter(writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the message to binary data (in protobuf wire format),
 * writing to the given BinaryWriter.
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.EncryptedPayload.prototype.serializeBinaryToWriter = function (writer) {
  var f = undefined;
  f = this.getSender();
  if (f !== 0) {
    writer.writeUint32(
      1,
      f
    );
  }
  f = this.getReceiversList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      2,
      f,
      proto.protobuf.Receiver.serializeBinaryToWriter
    );
  }
  f = this.getPayload_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      3,
      f
    );
  }
};


/**
 * Creates a deep clone of this proto. No data is shared with the original.
 * @return {!proto.protobuf.EncryptedPayload} The clone.
 */
proto.protobuf.EncryptedPayload.prototype.cloneMessage = function() {
  return /** @type {!proto.protobuf.EncryptedPayload} */ (jspb.Message.cloneMessage(this));
};


/**
 * optional uint32 Sender = 1;
 * @return {number}
 */
proto.protobuf.EncryptedPayload.prototype.getSender = function() {
  return /** @type {number} */ (jspb.Message.getFieldProto3(this, 1, 0));
};


/** @param {number} value  */
proto.protobuf.EncryptedPayload.prototype.setSender = function(value) {
  jspb.Message.setField(this, 1, value);
};


/**
 * repeated Receiver Receivers = 2;
 * If you change this array by adding, removing or replacing elements, or if you
 * replace the array itself, then you must call the setter to update it.
 * @return {!Array.<!proto.protobuf.Receiver>}
 */
proto.protobuf.EncryptedPayload.prototype.getReceiversList = function() {
  return /** @type{!Array.<!proto.protobuf.Receiver>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.protobuf.Receiver, 2));
};


/** @param {Array.<!proto.protobuf.Receiver>} value  */
proto.protobuf.EncryptedPayload.prototype.setReceiversList = function(value) {
  jspb.Message.setRepeatedWrapperField(this, 2, value);
};


proto.protobuf.EncryptedPayload.prototype.clearReceiversList = function() {
  this.setReceiversList([]);
};


/**
 * optional bytes Payload = 3;
 * @return {!(string|Uint8Array)}
 */
proto.protobuf.EncryptedPayload.prototype.getPayload = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldProto3(this, 3, ""));
};


/**
 * optional bytes Payload = 3;
 * This is a type-conversion wrapper around `getPayload()`
 * @return {string}
 */
proto.protobuf.EncryptedPayload.prototype.getPayload_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getPayload()));
};


/**
 * optional bytes Payload = 3;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getPayload()`
 * @return {!Uint8Array}
 */
proto.protobuf.EncryptedPayload.prototype.getPayload_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getPayload()));
};


/** @param {!(string|Uint8Array)} value  */
proto.protobuf.EncryptedPayload.prototype.setPayload = function(value) {
  jspb.Message.setField(this, 3, value);
};



/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.protobuf.Receiver = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.protobuf.Receiver, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.protobuf.Receiver.displayName = 'proto.protobuf.Receiver';
}


if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.protobuf.Receiver.prototype.toObject = function(opt_includeInstance) {
  return proto.protobuf.Receiver.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.protobuf.Receiver} msg The msg instance to transform.
 * @return {!Object}
 */
proto.protobuf.Receiver.toObject = function(includeInstance, msg) {
  var f, obj = {
    index: msg.getIndex(),
    encryptedkey: msg.getEncryptedkey_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.protobuf.Receiver}
 */
proto.protobuf.Receiver.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.protobuf.Receiver;
  return proto.protobuf.Receiver.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.protobuf.Receiver} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.protobuf.Receiver}
 */
proto.protobuf.Receiver.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setIndex(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setEncryptedkey(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Class method variant: serializes the given message to binary data
 * (in protobuf wire format), writing to the given BinaryWriter.
 * @param {!proto.protobuf.Receiver} message
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.Receiver.serializeBinaryToWriter = function(message, writer) {
  message.serializeBinaryToWriter(writer);
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.protobuf.Receiver.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  this.serializeBinaryToWriter(writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the message to binary data (in protobuf wire format),
 * writing to the given BinaryWriter.
 * @param {!jspb.BinaryWriter} writer
 */
proto.protobuf.Receiver.prototype.serializeBinaryToWriter = function (writer) {
  var f = undefined;
  f = this.getIndex();
  if (f !== 0) {
    writer.writeUint32(
      1,
      f
    );
  }
  f = this.getEncryptedkey_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
};


/**
 * Creates a deep clone of this proto. No data is shared with the original.
 * @return {!proto.protobuf.Receiver} The clone.
 */
proto.protobuf.Receiver.prototype.cloneMessage = function() {
  return /** @type {!proto.protobuf.Receiver} */ (jspb.Message.cloneMessage(this));
};


/**
 * optional uint32 Index = 1;
 * @return {number}
 */
proto.protobuf.Receiver.prototype.getIndex = function() {
  return /** @type {number} */ (jspb.Message.getFieldProto3(this, 1, 0));
};


/** @param {number} value  */
proto.protobuf.Receiver.prototype.setIndex = function(value) {
  jspb.Message.setField(this, 1, value);
};


/**
 * optional bytes EncryptedKey = 2;
 * @return {!(string|Uint8Array)}
 */
proto.protobuf.Receiver.prototype.getEncryptedkey = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldProto3(this, 2, ""));
};


/**
 * optional bytes EncryptedKey = 2;
 * This is a type-conversion wrapper around `getEncryptedkey()`
 * @return {string}
 */
proto.protobuf.Receiver.prototype.getEncryptedkey_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getEncryptedkey()));
};


/**
 * optional bytes EncryptedKey = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getEncryptedkey()`
 * @return {!Uint8Array}
 */
proto.protobuf.Receiver.prototype.getEncryptedkey_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getEncryptedkey()));
};


/** @param {!(string|Uint8Array)} value  */
proto.protobuf.Receiver.prototype.setEncryptedkey = function(value) {
  jspb.Message.setField(this, 2, value);
};

