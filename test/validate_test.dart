import 'package:btc_address_validate_swan/btc_address_validate_swan.dart';
import 'package:test/test.dart';

void main() {
  group('mainnet', () {
    group('non-segwit', () {
      test('pkh', () {
        expect(validate('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'),
            Address(Type.p2pkh, Network.mainnet, false));
      });

      test('sh', () {
        expect(validate('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'),
            Address(Type.p2sh, Network.mainnet, false));
      });
    });
    group('segwit', () {
      test('pkh', () {
        expect(validate('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'),
            Address(Type.p2pkh, Network.mainnet, true));
      });

      test('pkh-uppercase', () {
        expect(validate('BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ'),
            Address(Type.p2pkh, Network.mainnet, true));
      });

      test('sh', () {
        expect(
            validate(
                'bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9'),
            Address(Type.p2sh, Network.mainnet, true));
      });

      test('sh-uppercase', () {
        expect(
            validate(
                'BC1QC7SLRFXKKNQCQ2JEVVVKDGVRT8080852DFJEWDE450XDLK4UGP7SZW5TK9'),
            Address(Type.p2sh, Network.mainnet, true));
      });
    });

    group('taproot', () {
      test('p2tr', () {
        expect(
            validate(
                'bc1p5rknkun5t0qjyjgex4tdej86y0kqvphzfhf8g3a08zfgu7q36vms3sew4t'),
            Address(
              Type.p2tr,
              Network.mainnet,
              true,
            ));
      });
    });
  });
  group('testnet', () {
    group('non-segwit', () {
      test('pkh', () {
        expect(validate('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'),
            Address(Type.p2pkh, Network.testnet, false));
      });

      test('sh', () {
        expect(validate('2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc'),
            Address(Type.p2sh, Network.testnet, false));
      });
    });
    group('segwit', () {
      test('p2wkh', () {
        expect(validate('tb1qj4sqmsz8e8kqfwth8r2pfps2dnlergedyvg7ty'),
            Address(Type.p2pkh, Network.testnet, true));
      });
      test('sh', () {
        expect(
            validate(
                'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'),
            Address(Type.p2sh, Network.testnet, true));
      });
    });
  });

  group('exceptions:', () {
    test('too short', () {
      expect(
          () => validate('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN'),
          throwsA(predicate((e) =>
              e is FormatException &&
              e.message ==
                  'Too short: addresses must be at least 34 characters')));
    });
    test('p2pkh substitution error', () {
      expect(
          () => validate('1BvBMSEYstWetqTan5Au4m4GFg7xJaNVN2'),
          throwsA(predicate((e) =>
              e is Base58CheckException &&
              e.toString() ==
                  'Base58Check decoding exception: FormatException: Invalid checksum in Base58Check encoding.')));
    });

    test('p2pkh addition error', () {
      expect(
          () => validate('1BvBMSEYstWeatqTFn5Au4m4GFg7xJaNVN2'),
          throwsA(predicate((e) =>
              e is Base58CheckException &&
              e.toString() ==
                  'Base58Check decoding exception: FormatException: Invalid checksum in Base58Check encoding.')));
    });

    test('non-address version', () {
      expect(
          () => validate('4ESZo3E7YdsEACtbtCSMw7KbraW6inLYmQ'),
          throwsA(predicate((e) =>
              e is FormatException && e.message == 'Invalid Base58 version')));
    });

    test('segwit too long', () {
      expect(
          () => validate(
              'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90'),
          throwsA(predicate((dynamic e) =>
              e is SegwitException &&
              e.toString() ==
                  'SegWit decoding exception: Program length is invalid: too long')));
    });

    test('non-segwit too long', () {
      expect(
          () => validate('5Hwgr3u458GLafKBgxtssHSPqJnYoGrSzgQsPwLFhLNYskDPyyA'),
          throwsA(predicate((e) =>
              e is FormatException &&
              e.message == 'Invalid Base58 payload length')));
    });
  });
}
