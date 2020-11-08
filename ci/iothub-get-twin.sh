#!/bin/bash

# This script takes a module identity JSON obtained from IS and uses the info in it to create an MQTT connection to the IoT Hub.
# It then sends a request for the module twin, validates that the response is valid JSON, and prints it.
#
# Usage:
#
#     iothub-get-twin.sh "$(curl --unix-socket /run/aziot/identityd.sock 'http://foo/identities/modules/testmodule?api-version=2020-09-01')"


set -euo pipefail


uri_encode() {
    # Easier to just encode everything rather than characters outside the allowed set.
    printf '%s' "$1" |
        xxd -p |
        tr -d '\n' |
        sed -Ee 's/(..)/%\1/g'
}


# This is a tiny Azure IoT MQTT implementation that just authenticates as a module and fetches its twin.
#
# It would be nice to use mosquitto_rr instead of this, but https://github.com/eclipse/mosquitto/issues/1881
# Also, Debian 9's moquitto-clients package is old enough that it doesn't have mosquitto_rr anyway.
# For SAS identities we could work around that by generating the SAS token on the VM and then sending it back to
# the workflow runner, but that doesn't work for X.509 identities where the client must be able to talk to the KS
# via the aziot-keys openssl engine.

mqtt_client_get_twin() {
    (
        auth_type="$1"
        hub_name="$2"
        client_id="$3"
        username="$4"

        case "$auth_type" in
            'sas')
                password="$5"

                coproc CONNECTION {
                    openssl s_client -connect "$hub_name:8883" -quiet
                }
                ;;

            'x509')
                password=''
                key_handle="$5"
                cert_id="$(uri_encode "$6")"

                cert="$(
                    curl --unix-socket '/run/aziot/certd.sock' \
                        "http://foo/certificates/$cert_id?api-version=2020-09-01" |
                    jq '.pem' -r
                )"

                coproc CONNECTION {
                    openssl s_client \
                        -connect "$hub_name:8883" \
                        -key "$key_handle" -keyform engine \
                        -engine 'aziot_keys' \
                        -cert <(printf '%s' "$cert") \
                        -quiet
                }
                ;;

            *)
                exit 1
                ;;
        esac

        <&"${CONNECTION[0]}" timeout 10 perl -e '
            use strict;
            use warnings;

            sub write_packet {
                my ($fh, $type_and_flags, $payload) = @_;

                my $payload_length = length($payload);
                my $remaining_length = "";
                for (; ; ) {
                    my $b = int($payload_length % 128);
                    $payload_length = int($payload_length / 128);
                    if ($payload_length > 0) {
                        $remaining_length .= chr($b + 128);
                    }
                    else {
                        $remaining_length .= chr($b);
                        last;
                    }
                }

                print $fh $type_and_flags;
                print $fh $remaining_length;
                print $fh $payload;
            }

            sub read_packet {
                my $first_byte_read = read(STDIN, my $first_byte, 1);
                if ($first_byte_read != 1) {
                    die "EOF";
                }

                $first_byte = unpack("C", $first_byte);
                my $type = $first_byte & 0xF0;
                my $flags = $first_byte & 0x0F;

                my $remaining_length = 0;
                for (my $power = 0; ; $power++) {
                    my $bs_read = read(STDIN, my $bs, 1);
                    if ($bs_read != 1) {
                        die "EOF";
                    }
                    my $b = unpack("C", $bs);

                    if ($b >= 128) {
                        $remaining_length += ($b - 128) * (128 ** $power);
                    }
                    else {
                        $remaining_length += $b * (128 ** $power);
                        last;
                    }
                }

                my $payload_read = read(STDIN, my $payload, $remaining_length);
                if ($payload_read != $remaining_length) {
                    die "EOF";
                }

                return ($type, $flags, $payload);
            }


            # Write requests

            my $connection = shift;
            open(my $fh, ">", $connection) or die "could not open connection output file";
            select $fh; $| = 1; select STDOUT;

            my ($client_id, $username, $password) = @ARGV;

            # CONNECT { client_id: $client_id, username: $username, password: $password, will: None, clean_session: true, keep_alive: 1s }
            my $connect_payload =
                "\x00\x04MQTT" .
                "\x04";
            if ($password eq "") {
                $connect_payload .= "\x82"
            }
            else {
                $connect_payload .= "\xC2"
            }
            $connect_payload .=
                pack("n", 1) .
                pack("n", length($client_id)) . $client_id .
                pack("n", length($username)) . $username;
            if ($password ne "") {
                $connect_payload .= pack("n", length($password)) . $password;
            }
            write_packet($fh, "\x10", $connect_payload);

            # SUBSCRIBE { packet_identifier: 1, subscribe_to: [{ topic: $get_twin_response_topic, qos: AtMostOnce }] }
            my $get_twin_response_topic = "\$iothub/twin/res/#";
            my $subscribe_payload =
                "\x00\x01" .
                pack("n", length($get_twin_response_topic)) . $get_twin_response_topic . "\x00";
            write_packet($fh, "\x82", $subscribe_payload);

            # PUBLISH { topic: $get_twin_request_topic, payload: [], qos: AtMostOnce }
            my $get_twin_request_topic = "\$iothub/twin/GET/?\$rid=0";
            my $publish_payload =
                pack("n", length($get_twin_request_topic)) . $get_twin_request_topic;
            write_packet($fh, "\x30", $publish_payload);


            # Read responses

            my ($packet_type, $packet_flags, $packet_payload);

            # CONNACK { session_present: false, return_code: Accepted }
            ($packet_type, $packet_flags, $packet_payload) = read_packet();
            if ($packet_type != 0x20 || $packet_flags != 0) {
                die "expected CONNACK but got $packet_type:$packet_flags";
            }
            if ($packet_payload ne "\x00\x00") {
                die "connection failed";
            }

            # SUBACK { packet_identifier: 1, qos: [AtMostOnce] }
            ($packet_type, $packet_flags, $packet_payload) = read_packet();
            if ($packet_type != 0x90 || $packet_flags != 0) {
                die "expected SUBACK but got $packet_type:$packet_flags";
            }
            if ($packet_payload ne "\x00\x01\x00") {
                die "subscription failed";
            }

            # PUBLISH { dup: false, retain: false, qos: AtMostOnce, topic_name: "$iothub/twin/res/200/?$rid=1", payload }
            ($packet_type, $packet_flags, $packet_payload) = read_packet();
            if ($packet_type != 0x30 || $packet_flags != 0) {
                die "expected PUBLISH but got $packet_type:$packet_flags";
            }
            my $topic_length = unpack("n", substr($packet_payload, 0, 2));
            my $topic = substr($packet_payload, 2, $topic_length);
            if ($topic ne "\$iothub/twin/res/200/?\$rid=0") {
                die "expected PUBLISH with topic \"\$iothub/twin/res/200/?\$rid=0\" but got PUBLISH with topic \"$topic\"";
            }
            print substr($packet_payload, 2 + $topic_length);


            # DISCONNECT
            write_packet($fh, "\xE0", "");
        ' -- \
            "/proc/$BASHPID/fd/${CONNECTION[1]}" \
            "$client_id" \
            "$username" \
            "$password"
    ) | jq '.'
}


identity="$1"

hub_name="$(<<< "$identity" jq -r '.spec.hubName')"
device_id="$(<<< "$identity" jq -r '.spec.deviceId')"
module_id="$(<<< "$identity" jq -r '.spec.moduleId // ""')"
auth_type="$(<<< "$identity" jq -r '.spec.auth.type')"
key_handle="$(<<< "$identity" jq -r '.spec.auth.keyHandle')"

if [ -z "$module_id" ]; then
    resource_uri="$(printf '%s/devices/%s' "$hub_name" "$device_id" | sed -e 's|/|%2f|g')"
    client_id="$device_id"
    username="$hub_name/$device_id/?api-version=2018-06-30"
else
    resource_uri="$(printf '%s/devices/%s/modules/%s' "$hub_name" "$device_id" "$module_id" | sed -e 's|/|%2f|g')"
    client_id="$device_id/$module_id"
    username="$hub_name/$device_id/$module_id/?api-version=2018-06-30"
fi

case "$auth_type" in
    'sas')
        if [ -z "$module_id" ]; then
            # TODO: Bug? For device ID spec, the key handle is actually the key ID.
            key_id="$(uri_encode "$key_handle")"
            key_handle="$(
                curl --unix-socket '/run/aziot/keyd.sock' \
                    "http://foo/key/$key_id?api-version=2020-09-01" |
                    jq '.keyHandle' -er
            )"
        fi

        expiry="$(bc <<< "$(date +%s) + 60 * 60 * 24")"
        signature_data="$(printf '%s\n%s' "$resource_uri" "$expiry" | base64 -w 0)"
        signature="$(
            curl --unix-socket '/run/aziot/keyd.sock' \
                -X POST -H 'content-type: application/json' --data-binary "$(
                    jq -cn --arg 'keyHandle' "$key_handle" --arg 'message' "$signature_data" '{
                        "keyHandle": $keyHandle,
                        "algorithm": "HMAC-SHA256",
                        "parameters": {
                            "message": $message,
                        },
                    }'
                )" 'http://foo/sign?api-version=2020-09-01' |
                jq '.signature' -er |
                sed -e 's|+|%2b|g' -e 's|/|%2f|g' -e 's|=|%3d|g'
        )"
        sas_token="$(printf 'sr=%s&se=%s&sig=%s' "$resource_uri" "$expiry" "$signature")"
        password="SharedAccessSignature $sas_token"

        mqtt_client_get_twin \
            "$auth_type" \
            "$hub_name" \
            "$client_id" \
            "$username" \
            "$password" |
            jq '.'
        ;;

    'x509')
        password=''
        cert_id="$(<<< "$identity" jq -er '.spec.auth.certId')"

        mqtt_client_get_twin \
            "$auth_type" \
            "$hub_name" \
            "$client_id" \
            "$username" \
            "$key_handle" \
            "$cert_id" |
            jq '.'
        ;;

    *)
        echo "Unexpected auth type $auth_type" >&2
        exit 1
esac
