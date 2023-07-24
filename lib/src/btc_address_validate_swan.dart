import 'dart:typed_data';

import 'package:base58check/base58check.dart';
import 'package:dart_bech32/dart_bech32.dart';
import 'package:equatable/equatable.dart';
import 'package:bech32/bech32.dart';

enum Type {
  p2pkh,
  p2sh,

  // Taproot
  p2tr,
}

enum Network { mainnet, testnet }

class Address extends Equatable {
  Address(this.type, this.network, this.segwit);

  final Type? type;
  final Network? network;
  final bool segwit;

  @override
  List<Object?> get props => [type, network, segwit];

  @override
  String toString() =>
      '[Address type: $type, network: $network, segwit: $segwit]';
}

const Map<int, Network> versionToNetwork = {
  0: Network.mainnet,
  5: Network.mainnet,
  111: Network.testnet,
  196: Network.testnet,
};

const Map<int, Type> versionToType = {
  0: Type.p2pkh,
  5: Type.p2sh,
  111: Type.p2pkh,
  196: Type.p2sh,
};

const minLength = 27;

Address validate(String address) {
  if (address.length < minLength) {
    throw FormatException(
        'Too short: addresses must be at least $minLength characters');
  }

  /// First try to parse as taproot / segwit
  final prefix = address.substring(0, 2).toLowerCase();
  if (prefix == 'bc' || prefix == 'tb') {
    return validateSegwit(address);
  }

  final codec = Base58CheckCodec.bitcoin();
  Base58CheckPayload decoded;
  try {
    decoded = codec.decode(address);
  } catch (e) {
    throw Base58CheckException(e);
  }
  if (decoded.payload.length != 20) {
    throw FormatException('Invalid Base58 payload length');
  }

  final version = decoded.version;
  if (!versionToType.keys.contains(version)) {
    throw FormatException('Invalid Base58 version');
  }
  return Address(
    versionToType[version]!,
    versionToNetwork[version]!,
    false,
  );
}

Address validateSegwit(String address) {
  final prefix = address.substring(0, 2).toLowerCase();
  Decoded decoded;

  /// Try to decode the address using bech32m
  try {
    final _decoded = segwit.decode(address);
    decoded = Decoded(
      prefix: prefix,
      words: Uint8List.fromList(
        _decoded.program,
      ),
    );
  } on InvalidChecksum {
    decoded = bech32m.decode(Encoded(data: address));
  } catch (e) {
    throw SegwitException(e);
  }

  late Type type;
  // other lengths result in a [SegwitException]
  switch (decoded.words.length) {
    /// P2WPKH
    case 20:
      type = Type.p2pkh;
      break;

    /// P2WSH
    case 32:
      type = Type.p2sh;
      break;

    /// P2TR
    case 53:
      type = Type.p2tr;
      break;

    /// Other
    default:
      throw SegwitException('Invalid words length: ${decoded.words.length}');
  }

  late Network network;
  switch (prefix) {
    case 'bc':
      {
        network = Network.mainnet;
      }
      break;
    case 'tb':
      {
        network = Network.testnet;
      }
  }

  return Address(type, network, true);
}

class SegwitException implements Exception {
  SegwitException(this.inner);

  final Object inner;

  @override
  String toString() => 'SegWit decoding exception: $inner';
}

class Base58CheckException implements Exception {
  Base58CheckException(this.inner);

  final Object inner;

  @override
  String toString() => 'Base58Check decoding exception: $inner';
}
