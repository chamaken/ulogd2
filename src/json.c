#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#include <ulogd/ulogd.h>
#include <ulogd/ipfix_protocol.h>

#define ccmp(s, t) do { if (strncmp(s, (#t), strlen(#t)) == 0) return (t); } while (0)

static int key_type(const char *const type)
{
	/* return -1 on error or can be casted to uint16_t */
	if (type == NULL) return -1;
	ccmp(type, ULOGD_RET_INT8);
	ccmp(type, ULOGD_RET_INT16);
	ccmp(type, ULOGD_RET_INT32);
	ccmp(type, ULOGD_RET_INT64);
	ccmp(type, ULOGD_RET_UINT8);
	ccmp(type, ULOGD_RET_UINT16);
	ccmp(type, ULOGD_RET_UINT32);
	ccmp(type, ULOGD_RET_UINT64);
	ccmp(type, ULOGD_RET_BOOL);
	ccmp(type, ULOGD_RET_IPADDR);
	ccmp(type, ULOGD_RET_IP6ADDR);
	ccmp(type, ULOGD_RET_STRING);
	ccmp(type, ULOGD_RET_RAW);
	ccmp(type, ULOGD_RET_RAWSTR);
	/* ULOGD_RET_NONE is an error */
	return -1;
}

static int key_flag(const char *const flag)
{
	/* return -1 on error or can be casted to uint16_t */
	if (flag == NULL) return -1;
	ccmp(flag, ULOGD_RETF_NONE);
	ccmp(flag, ULOGD_RETF_VALID);
	ccmp(flag, ULOGD_RETF_FREE);
	ccmp(flag, ULOGD_RETF_NEEDED);
	ccmp(flag, ULOGD_RETF_DESTRUCT);
	ccmp(flag, ULOGD_RETF_EMBED);
	ccmp(flag, ULOGD_KEYF_OPTIONAL);
	ccmp(flag, ULOGD_KEYF_INACTIVE);

	return -1;
}

static int config_type(const char *const type)
{
	/* return -1 on error or can be casted to uint8_t */
	if (type == NULL) return -1;
	ccmp(type, CONFIG_TYPE_INT);
	ccmp(type, CONFIG_TYPE_STRING);
	ccmp(type, CONFIG_TYPE_CALLBACK);

	return -1;
}

static int config_option(const char *const option)
{
	/* return -1 on error or can be casted to uint8_t */
	if (option == NULL) return -1;
	ccmp(option, CONFIG_OPT_NONE);
	ccmp(option, CONFIG_OPT_MANDATORY);
	ccmp(option, CONFIG_OPT_MULTI);

	return -1;
}

static int ipfix_vendor(const char *const vendor)
{
	ccmp(vendor, IPFIX_VENDOR_IETF);
	ccmp(vendor, IPFIX_VENDOR_NETFILTER);
	ccmp(vendor, IPFIX_VENDOR_REVERSE);

	return -1;
}

/* XXX: use gperf? */
static int ipfix_field_id(const char *const field_id)
{
	ccmp(field_id, IPFIX_octetDeltaCount);
	ccmp(field_id, IPFIX_packetDeltaCount);
	ccmp(field_id, IPFIX_protocolIdentifier);
	ccmp(field_id, IPFIX_classOfServiceIPv4);
	ccmp(field_id, IPFIX_tcpControlBits);
	ccmp(field_id, IPFIX_sourceTransportPort);
	ccmp(field_id, IPFIX_sourceIPv4Address);
	ccmp(field_id, IPFIX_sourceIPv4Mask);
	ccmp(field_id, IPFIX_ingressInterface);
	ccmp(field_id, IPFIX_destinationTransportPort);
	ccmp(field_id, IPFIX_destinationIPv4Address);
	ccmp(field_id, IPFIX_destinationIPv4Mask);
	ccmp(field_id, IPFIX_egressInterface);
	ccmp(field_id, IPFIX_ipNextHopIPv4Address);
	ccmp(field_id, IPFIX_bgpSourceAsNumber);
	ccmp(field_id, IPFIX_bgpDestinationAsNumber);
	ccmp(field_id, IPFIX_bgpNextHopIPv4Address);
	ccmp(field_id, IPFIX_postMCastPacketDeltaCount);
	ccmp(field_id, IPFIX_postMCastOctetDeltaCount);
	ccmp(field_id, IPFIX_flowEndSysUpTime);
	ccmp(field_id, IPFIX_flowStartSysUpTime);
	ccmp(field_id, IPFIX_postOctetDeltaCount);
	ccmp(field_id, IPFIX_postPacketDeltaCount);
	ccmp(field_id, IPFIX_minimumPacketLength);
	ccmp(field_id, IPFIX_maximumPacketLength);
	ccmp(field_id, IPFIX_sourceIPv6Address);
	ccmp(field_id, IPFIX_destinationIPv6Address);
	ccmp(field_id, IPFIX_sourceIPv6Mask);
	ccmp(field_id, IPFIX_destinationIPv6Mask);
	ccmp(field_id, IPFIX_flowLabelIPv6);
	ccmp(field_id, IPFIX_icmpTypeCodeIPv4);
	ccmp(field_id, IPFIX_igmpType);
	ccmp(field_id, IPFIX_flowActiveTimeOut);
	ccmp(field_id, IPFIX_flowInactiveTimeout);
	ccmp(field_id, IPFIX_exportedOctetTotalCount);
	ccmp(field_id, IPFIX_exportedMessageTotalCount);
	ccmp(field_id, IPFIX_exportedFlowTotalCount);
	ccmp(field_id, IPFIX_sourceIPv4Prefix);
	ccmp(field_id, IPFIX_destinationIPv4Prefix);
	ccmp(field_id, IPFIX_mplsTopLabelType);
	ccmp(field_id, IPFIX_mplsTopLabelIPv4Address);
	ccmp(field_id, IPFIX_minimumTtl);
	ccmp(field_id, IPFIX_maximumTtl);
	ccmp(field_id, IPFIX_identificationIPv4);
	ccmp(field_id, IPFIX_postClassOfServiceIPv4);
	ccmp(field_id, IPFIX_sourceMacAddress);
	ccmp(field_id, IPFIX_postDestinationMacAddr);
	ccmp(field_id, IPFIX_vlanId);
	ccmp(field_id, IPFIX_postVlanId);
	ccmp(field_id, IPFIX_ipVersion);
	ccmp(field_id, IPFIX_flowDirection);
	ccmp(field_id, IPFIX_ipNextHopIPv6Address);
	ccmp(field_id, IPFIX_bgpNexthopIPv6Address);
	ccmp(field_id, IPFIX_ipv6ExtensionHeaders);
	ccmp(field_id, IPFIX_mplsTopLabelStackEntry);
	ccmp(field_id, IPFIX_mplsLabelStackEntry2);
	ccmp(field_id, IPFIX_mplsLabelStackEntry3);
	ccmp(field_id, IPFIX_mplsLabelStackEntry4);
	ccmp(field_id, IPFIX_mplsLabelStackEntry5);
	ccmp(field_id, IPFIX_mplsLabelStackEntry6);
	ccmp(field_id, IPFIX_mplsLabelStackEntry7);
	ccmp(field_id, IPFIX_mplsLabelStackEntry8);
	ccmp(field_id, IPFIX_mplsLabelStackEntry9);
	ccmp(field_id, IPFIX_mplsLabelStackEntry10);
	ccmp(field_id, IPFIX_destinationMacAddress);
	ccmp(field_id, IPFIX_postSourceMacAddress);
	ccmp(field_id, IPFIX_octetTotalCount);
	ccmp(field_id, IPFIX_packetTotalCount);
	ccmp(field_id, IPFIX_fragmentOffsetIPv4);
	ccmp(field_id, IPFIX_bgpNextAdjacentAsNumber);
	ccmp(field_id, IPFIX_bgpPrevAdjacentAsNumber);
	ccmp(field_id, IPFIX_exporterIPv4Address);
	ccmp(field_id, IPFIX_exporterIPv6Address);
	ccmp(field_id, IPFIX_droppedOctetDeltaCount);
	ccmp(field_id, IPFIX_droppedPacketDeltaCount);
	ccmp(field_id, IPFIX_droppedOctetTotalCount);
	ccmp(field_id, IPFIX_droppedPacketTotalCount);
	ccmp(field_id, IPFIX_flowEndReason);
	ccmp(field_id, IPFIX_classOfServiceIPv6);
	ccmp(field_id, IPFIX_postClassOFServiceIPv6);
	ccmp(field_id, IPFIX_icmpTypeCodeIPv6);
	ccmp(field_id, IPFIX_mplsTopLabelIPv6Address);
	ccmp(field_id, IPFIX_lineCardId);
	ccmp(field_id, IPFIX_portId);
	ccmp(field_id, IPFIX_meteringProcessId);
	ccmp(field_id, IPFIX_exportingProcessId);
	ccmp(field_id, IPFIX_templateId);
	ccmp(field_id, IPFIX_wlanChannelId);
	ccmp(field_id, IPFIX_wlanSsid);
	ccmp(field_id, IPFIX_flowId);
	ccmp(field_id, IPFIX_sourceId);
	ccmp(field_id, IPFIX_flowStartSeconds);
	ccmp(field_id, IPFIX_flowEndSeconds);
	ccmp(field_id, IPFIX_flowStartMilliSeconds);
	ccmp(field_id, IPFIX_flowEndMilliSeconds);
	ccmp(field_id, IPFIX_flowStartMicroSeconds);
	ccmp(field_id, IPFIX_flowEndMicroSeconds);
	ccmp(field_id, IPFIX_flowStartNanoSeconds);
	ccmp(field_id, IPFIX_flowEndNanoSeconds);
	ccmp(field_id, IPFIX_flowStartDeltaMicroSeconds);
	ccmp(field_id, IPFIX_flowEndDeltaMicroSeconds);
	ccmp(field_id, IPFIX_systemInitTimeMilliSeconds);
	ccmp(field_id, IPFIX_flowDurationMilliSeconds);
	ccmp(field_id, IPFIX_flowDurationMicroSeconds);
	ccmp(field_id, IPFIX_observedFlowTotalCount);
	ccmp(field_id, IPFIX_ignoredPacketTotalCount);
	ccmp(field_id, IPFIX_ignoredOctetTotalCount);
	ccmp(field_id, IPFIX_notSentFlowTotalCount);
	ccmp(field_id, IPFIX_notSentPacketTotalCount);
	ccmp(field_id, IPFIX_notSentOctetTotalCount);
	ccmp(field_id, IPFIX_destinationIPv6Prefix);
	ccmp(field_id, IPFIX_sourceIPv6Prefix);
	ccmp(field_id, IPFIX_postOctetTotalCount);
	ccmp(field_id, IPFIX_postPacketTotalCount);
	ccmp(field_id, IPFIX_flowKeyIndicator);
	ccmp(field_id, IPFIX_postMCastPacketTotalCount);
	ccmp(field_id, IPFIX_postMCastOctetTotalCount);
	ccmp(field_id, IPFIX_icmpTypeIPv4);
	ccmp(field_id, IPFIX_icmpCodeIPv4);
	ccmp(field_id, IPFIX_icmpTypeIPv6);
	ccmp(field_id, IPFIX_icmpCodeIPv6);
	ccmp(field_id, IPFIX_udpSourcePort);
	ccmp(field_id, IPFIX_udpDestinationPort);
	ccmp(field_id, IPFIX_tcpSourcePort);
	ccmp(field_id, IPFIX_tcpDestinationPort);
	ccmp(field_id, IPFIX_tcpSequenceNumber);
	ccmp(field_id, IPFIX_tcpAcknowledgementNumber);
	ccmp(field_id, IPFIX_tcpWindowSize);
	ccmp(field_id, IPFIX_tcpUrgentPointer);
	ccmp(field_id, IPFIX_tcpHeaderLength);
	ccmp(field_id, IPFIX_ipHeaderLength);
	ccmp(field_id, IPFIX_totalLengthIPv4);
	ccmp(field_id, IPFIX_payloadLengthIPv6);
	ccmp(field_id, IPFIX_ipTimeToLive);
	ccmp(field_id, IPFIX_nextHeaderIPv6);
	ccmp(field_id, IPFIX_ipClassOfService);
	ccmp(field_id, IPFIX_ipDiffServCodePoint);
	ccmp(field_id, IPFIX_ipPrecedence);
	ccmp(field_id, IPFIX_fragmentFlagsIPv4);
	ccmp(field_id, IPFIX_octetDeltaSumOfSquares);
	ccmp(field_id, IPFIX_octetTotalSumOfSquares);
	ccmp(field_id, IPFIX_mplsTopLabelTtl);
	ccmp(field_id, IPFIX_mplsLabelStackLength);
	ccmp(field_id, IPFIX_mplsLabelStackDepth);
	ccmp(field_id, IPFIX_mplsTopLabelExp);
	ccmp(field_id, IPFIX_ipPayloadLength);
	ccmp(field_id, IPFIX_udpMessageLength);
	ccmp(field_id, IPFIX_isMulticast);
	ccmp(field_id, IPFIX_internetHeaderLengthIPv4);
	ccmp(field_id, IPFIX_ipv4Options);
	ccmp(field_id, IPFIX_tcpOptions);
	ccmp(field_id, IPFIX_paddingOctets);
	ccmp(field_id, IPFIX_headerLengthIPv4);
	ccmp(field_id, IPFIX_mplsPayloadLength);
	ccmp(field_id, IPFIX_postNATSourceIPv4Address);
	ccmp(field_id, IPFIX_postNATDestinationIPv4Address);
	ccmp(field_id, IPFIX_postNAPTSourceTransportPort);
	ccmp(field_id, IPFIX_postNAPTDestinationTransportPort);
	ccmp(field_id, IPFIX_firewallEvent);
	ccmp(field_id, IPFIX_postNATSourceIPv6Address);
	ccmp(field_id, IPFIX_postNATDestinationIPv6Address);
	ccmp(field_id, IPFIX_NF_rawpacket);
	ccmp(field_id, IPFIX_NF_rawpacket_length);
	ccmp(field_id, IPFIX_NF_prefix);
	ccmp(field_id, IPFIX_NF_mark);
	ccmp(field_id, IPFIX_NF_hook);
	ccmp(field_id, IPFIX_NF_conntrack_id);
	ccmp(field_id, IPFIX_NF_seq_local);
	ccmp(field_id, IPFIX_NF_seq_global);

	return -1;
};

#undef ccmp

static int parse_config_entry(struct config_entry *const ce, json_t *const json, int seq)
{
	const char *key, *typestr;
	int type, option, keylen;
	size_t i, array_size;
	json_t *array, *jvalue = NULL;
	json_error_t error;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s, s:o, s?o}",
			   "key", &key, &keylen,
			   "type", &typestr,
			   "options", &array,
			   "value", &jvalue) < 0) {
		ulogd_log(ULOGD_ERROR, "config_entry[%d] error line %d: %s\n",
			  seq, error.line, error.text);
		return -1;
	}
	if (keylen > CONFIG_KEY_LEN) {
		ulogd_log(ULOGD_ERROR,
			  "too long config_kset[%d].key size\n", seq);
		return -ENAMETOOLONG;
	}
	strncpy(ce->key, key, CONFIG_KEY_LEN);

	if ((type = config_type(typestr)) == -1) {
		ulogd_log(ULOGD_ERROR, "invalid config_kset[%d].type: %s\n",
			  seq, typestr);
		return -EINVAL;
	}
	ce->type = (uint8_t)type;

	ce->options = 0;
	if (!json_is_array(array)) {
		ulogd_log(ULOGD_ERROR,
			  "config_kset[%d].options is not an array\n", seq);
		return -EINVAL;
	}
	array_size = json_array_size(array);
	for (i = 0; i < array_size; i++) {
		option = config_option(json_string_value(json_array_get(array, i)));
		if (option < 0) {
			ulogd_log(ULOGD_ERROR,
				  "invalid config_kset[%d].options\n", seq);
			return -EINVAL;
		}
		ce->options |= (uint8_t)option;
	}

	return 0;
}

int parse_alloc_config(struct config_keyset **ck, const json_t *const json)
{
	size_t i, array_size, size;
	int ret = 0;

	size = sizeof(struct config_keyset);
	array_size = json_array_size(json);
	size += array_size * sizeof(struct config_entry);
	*ck = calloc(1, size);
	if (*ck == NULL)
		return -ENOMEM;
	if (((*ck)->num_ces = array_size) == 0)
		return 0;

	for (i = 0; i < array_size; i++) {
		ret = parse_config_entry(&((*ck)->ces[i]), json_array_get(json, i), i);
		if (ret < 0)
			goto failure;
	}

	return i;
failure:
	free(*ck);
	return ret;
}

int parse_ipfix(struct ulogd_key *key, struct json_t *const json, int seq)
{
	json_error_t error;
	char *vendor_str, *id_str;
	int vendor, id;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s, s:s}",
			   "vendor", &vendor_str,
			   "field_id", &id_str) < 0) {
		ulogd_log(ULOGD_ERROR, "invalid key[%d].ipfix\n", seq);
		return -EINVAL;
	}
	vendor = ipfix_vendor(vendor_str);
	if (vendor < 0) {
		ulogd_log(ULOGD_ERROR, "invalid key[%d].iprix.vendor\n", seq);
		return -EINVAL;
	}
	key->ipfix.vendor = (uint32_t)vendor;

	id = ipfix_field_id(id_str);
	if (id < 0) {
		ulogd_log(ULOGD_ERROR, "invalid key[%d].ipfix.field_id\n", seq);
		return -EINVAL;
	}
	key->ipfix.field_id = (uint16_t)id;

	return 0;
}

int parse_key(struct ulogd_key *key, struct json_t *const json, int seq)
{
	json_error_t error;
	int keylen = 0, namelen, cimlen, type, flag;
	char *typestr, *name, *cim_name = NULL, *destruct = NULL;
	json_t *array, *ipfix = NULL;
	size_t array_size, i;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s?i, s:s, s:o, s%:s, s?o, s%?s, s?s}",
			   "len", &keylen,
			   "type", &typestr,
			   "flags", &array,
			   "name", &name, &namelen,
			   "ipfix", &ipfix,
			   "cim_name", &cim_name, &cimlen,
			   "destruct", &destruct) < 0) {
		ulogd_log(ULOGD_ERROR, "invalid key[%d]\n", seq);
		return -1;
	}

	type = key_type(typestr);
	if (type < 0) {
		ulogd_log(ULOGD_ERROR, "invalid key[%d].type\n", seq);
		return -EINVAL;
	}
	key->type = (uint16_t)type;
	if (type == ULOGD_RET_RAW) { /* how about RAWSTR? */
		key->len = (uint32_t)keylen;
	} else if (keylen != 0) {
		ulogd_log(ULOGD_NOTICE, "len is valid only for RAW\n");
	}

	if (!json_is_array(array)) {
		ulogd_log(ULOGD_ERROR, "flags must be an array\n");
		return -EINVAL;
	}
	key->flags = 0;
	array_size = json_array_size(array);
	for (i = 0; i < array_size; i++) {
		flag = key_flag(json_string_value(json_array_get(array, i)));
		if (flag < 0) {
			ulogd_log(ULOGD_ERROR, "invalid key[%d].flag\n", seq);
			return -EINVAL;
		}
		key->flags |= (uint16_t)flag;
	}

	if (namelen > ULOGD_MAX_KEYLEN) {
		ulogd_log(ULOGD_ERROR, "too long key[%d].name\n", seq);
		return -EINVAL;
	}
	strncpy(key->name, name, ULOGD_MAX_KEYLEN);

	if (cimlen > ULOGD_MAX_KEYLEN) {
		ulogd_log(ULOGD_ERROR, "too long key[%d].cim_name\n", seq);
		return -EINVAL;
	}
	strncpy(key->cim_name, cim_name, ULOGD_MAX_KEYLEN);

	if (!json_is_object(ipfix)) {
		ulogd_log(ULOGD_ERROR,
			  "key[%d].ipfix must be an object\n", seq);
		return -EINVAL;
	}
	return parse_ipfix(key, ipfix, seq);
}

int parse_alloc_keyset(struct ulogd_keyset *kset, struct json_t *const json)
{

	json_t *array = NULL;
	json_error_t error;
	size_t array_size, i;
	char *type;
	int ret;

	if (json_unpack_ex(json, &error, JSON_STRICT, "{s:s, s?o}",
			   "type", &type, "keys", &array) < 0) {
		ulogd_log(ULOGD_ERROR, "keyset error on line: %d, %s\n",
			  error.line, error.text);
		return -1;
	}
	if (key_type(type) < 0) {
		ulogd_log(ULOGD_ERROR, "invalid keyset.type: %s\n", type);
		return -1;
	}
	if (array && !json_is_array(array)) {
		ulogd_log(ULOGD_ERROR, "invalid keyset.keys\n");
		return -EINVAL;
	}

	if (array == NULL)
		array_size = 0;
	else
		array_size = json_array_size(array);
	kset->keys = calloc(1, array_size * sizeof(struct ulogd_key));
	if (kset->keys == NULL)
		return -ENOMEM;

	kset->type = (unsigned int)key_type(type);
	kset->num_keys = array_size;
	if (array_size == 0) {
		kset->keys = NULL;
		return 0;
	}

	for (i = 0; i < array_size; i++) {
		ret = parse_key(&(kset->keys[i]),
				json_array_get(array, i), i);
		if (ret < 0)
			goto free_kset;
	}

	return 0;
	
free_kset:
	free(kset);
	return ret;
}

/*
 * struct config_entry
 *   key: string (required < CONFIG_KEY_LEN)
 *   type: string (required)
 *   options: [string]
 *   value: int or string (optional)
 * "{s%:s, s:s, s:o, s?o}", "key", "type", "options", "value"
 *
 * struct ipfix
 *   vendor: string (required)
 *   field_id: string (required)
 * "{s:s, s:s}", "vendor", "field_id"
 *
 * struct ulogd_key:
 *   len: int (optional for RAW)
 *   type: string (required)
 *   flags: [string] (required)
 *   name: string (required < ULOGD_MAX_KEYLEN)
 *   ipfix: --- ipfix ---
 *   cim_name: string (optional < ULOGD_MAX_KEYLEN)
 *   destruct: string (optional - function)
 * "{s?i, s:s, s:o, s%:s, s:o, s?s%, s?s}"
 *   "len", "type", "flags", "name", "ipfix", "cim_name", "destruct"
 *
 * struct ulogd_keyset:
 *   keys: [--- ulogd_key ---] (optional)
 *   type: string (required)
 * "{s?o, s:s}, "keys", "type"
 *
 * struct ulogd_plugin:
 *   version: string (required < ULOGD_MAX_VERLEN)
 *   name: string (required < ULOGD_MAX_KEYLEN)
 *   # priv_size: int (non-python)
 *   config_keyset: [--- config_entry ---] (optional)
 *   output: --- ulogd_keyset --- (optional - sink_plugin?)
 *   input: --- ulogd_keyset --- (required)
 *   configure: string (optional - function)
 *   start: string (optional - function)
 *   stop: string (optional - function)
 *   signal: string (optional - function)
 *   interp: string (required - function)
 * "{s:s%, s:s%, s?o, s:o, s:o, s:s, s:s, s:s, s:s, s:s}",
 *   "version", "name", "config_kset",
 *   "output", "intput",
 *   "configure", "start", "stop", "signal", "interp"
 *
 * struct ulogd_source_plugin
 *   version: string (required < ULOGD_MAX_VERLEN)
 *   name: string (required < ULOGD_MAX_KEYLEN)
 *   # priv_size: int (non-python)
 *   config_kset: [--- config_entry ---] (optional)
 *   output: --- ulogd_keyset --- (required)
 *   configure: string (optional - function)
 *   start: string (required? - function)
 *   stop: string (required? - function)
 *   signal: string (optional - function)
 * "{s:s%, s:s%, s?o, s:o, s?s, s:s, s:s, s?s}"
 *   "version", "name", "config_kset", "output",
 *   "configure", "start", "stop, "signal"
 */
struct ulogd_plugin *ulogd_plugin_json(const char *const fname)
{
	json_t *root;
	json_t *input, *output, *config_kset = NULL;
	json_error_t error;
	char *version, *name;
	char *configure = NULL, *start = NULL, *stop = NULL;
	char *signal = NULL, *interp = NULL;
	size_t verlen, namelen;
	int ret;
	struct ulogd_plugin *pl
		= calloc(1, sizeof(struct ulogd_plugin));

	if (pl == NULL)
		return NULL;
	
	root = json_load_file(fname, JSON_REJECT_DUPLICATES, &error);
	if (!root) {
		ulogd_log(ULOGD_ERROR, "error on line %d: %s\n",
			  error.line, error.text);
		goto fail_free;
	}

	if (json_unpack_ex(root, &error, JSON_STRICT,
			   "{s:s%, s:s%, s:o, s:o, s?o, s?s, s?s, s?s, s?s, s:s}",
			   "version", &version, &verlen,
			   "name", &name, &namelen,
			   "input", &input,
			   "output", &output,
			   "config_kset", &config_kset,
			   "configure", &configure,
			   "start", &start,
			   "stop", &stop,
			   "signal", &signal,
			   "interp", &interp) < 0) {
		ulogd_log(ULOGD_ERROR, "plugin error on line %d: %s\n",
			  error.line, error.text);
		goto fail_free;
	}

	/* version */
	if (verlen > ULOGD_MAX_VERLEN) {
		ulogd_log(ULOGD_ERROR, "plugin - too long version length\n");
		goto fail_free;
	}
	strncpy(pl->version, version, ULOGD_MAX_VERLEN);

	/* name */
	if (namelen > ULOGD_MAX_KEYLEN) {
		ulogd_log(ULOGD_ERROR, "plugin - too long name length\n");
		goto fail_free;
	}
	strncpy(pl->name, name, ULOGD_MAX_KEYLEN);

	/* input */
	if (!json_is_object(input)) {
		ulogd_log(ULOGD_ERROR, "plugin - input is not an object\n");
		goto fail_free;
	}
	ret = parse_alloc_keyset(&pl->input, input);
	if (ret < 0)
		goto fail_free;
	
	/* output */
	if (!json_is_object(output)) {
		ulogd_log(ULOGD_ERROR, "plugin - output is not an object\n");
		ret = -EINVAL;
		goto fail_free;
	}
	ret = parse_alloc_keyset(&pl->output, output);
	if (ret < 0)
		goto fail_free;

	/* config_kset */
	if (config_kset != NULL) {
		if (!json_is_array(config_kset)) {
			ulogd_log(ULOGD_ERROR,
				  "plugin - config_kset is not an array\n");
			ret = -EINVAL;
			goto fail_free;
		}
		ret = parse_alloc_config(&pl->config_kset, config_kset);
		if (ret < 0)
			goto fail_free;
	}

	json_decref(root);
	return pl;

fail_free:
	free(pl);
	json_decref(root);
	return NULL;
}
	     
struct ulogd_source_plugin *ulogd_source_plugin_json(const char *const fname)
{
	json_t *root;
	json_t *output, *config_kset = NULL;
	json_error_t error;
	char *version, *name;
	char *configure = NULL, *start = NULL, *stop = NULL, *signal = NULL;
	size_t verlen, namelen;
	int ret;
	struct ulogd_source_plugin *sp
		= calloc(1, sizeof(struct ulogd_source_plugin));

	if (sp == NULL)
		return NULL;

	root = json_load_file(fname, JSON_REJECT_DUPLICATES, &error);
	if (!root) {
		ulogd_log(ULOGD_ERROR, "error on line %d: %s\n",
			  error.line, error.text);
		goto fail_free;
	}

	if (json_unpack_ex(root, &error, JSON_STRICT,
			   "{s:s%, s:s%, s?o, s:o, s?s, s:s, s:s, s?s}",
			   "version", &version, &verlen,
			   "name", &name, &namelen,
			   "config_kset", &config_kset,
			   "output", &output,
			   "configure", &configure,
			   "start", &start,
			   "stop", &stop,
			   "signal", &signal) < 0) {
		ulogd_log(ULOGD_ERROR, "source plugin error on line %d: %s\n",
			  error.line, error.text);
		goto fail_free;
	}

	/* version */
	if (verlen > ULOGD_MAX_VERLEN) {
		ulogd_log(ULOGD_ERROR, "source plugin -"
			  " too long version length\n");
		goto fail_free;
	}
	strncpy(sp->version, version, ULOGD_MAX_VERLEN);

	/* name */
	if (namelen > ULOGD_MAX_KEYLEN) {
		ulogd_log(ULOGD_ERROR, "source plugin -"
			  " too long name length\n");
		goto fail_free;
	}
	strncpy(sp->name, name, ULOGD_MAX_KEYLEN);

	/* output */
	if (!json_is_object(output)) {
		ulogd_log(ULOGD_ERROR, "source plugin -"
			  " output is not an object\n");
		goto fail_free;
	}
	ret = parse_alloc_keyset(&sp->output, output);
	if (ret < 0)
		goto fail_free;

	/* config_kset */
	if (config_kset != NULL) {
		if (!json_is_array(config_kset)) {
			ulogd_log(ULOGD_ERROR, "source plugin -"
				  " config_kset is not an array\n");
			goto fail_free;
		}
		ret = parse_alloc_config(&sp->config_kset, config_kset);
		if (ret < 0)
			goto fail_free;
	}

	json_decref(root);
	return sp;

fail_free:
	free(sp);
	json_decref(root);
	return NULL;
}
