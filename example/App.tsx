import {Button, ScrollView, Text, View} from 'react-native';
import React from 'react';
import {DG1, DG15, PRIVATE_KEY, SOD} from '@env';
import {Buffer} from 'buffer';
import {
  Rarime,
  RarimeConfiguration,
  RarimePassport,
  RarimeUtils,
} from '@rarimo/rarime-rn-sdk';

export default function App() {
  const [busy, setBusy] = React.useState(false);
  return (
      <View style={styles.container}>
        <ScrollView style={styles.container}>
          <Text style={styles.header}>Module API Example</Text>
          <Button
              title="lite register"
              disabled={busy}
              onPress={async () => {
                try {
                  setBusy(true);
                  const userPrivateKey =
                      PRIVATE_KEY && PRIVATE_KEY.length > 0
                          ? PRIVATE_KEY
                          : RarimeUtils.generateBJJPrivateKey();

                  console.log(userPrivateKey);

                  const rarimeConfig: RarimeConfiguration = {
                    contractsConfiguration: {
                      stateKeeperAddress:
                          '0x12883d5F530AF7EC2adD7cEC29Cf84215efCf4D8',
                      registerSimpleContractAddress:
                          '0x1b6ae4b80F0f26DC53731D1d7aA31fc3996B513B',
                      poseidonSmtAddress:
                          '0xb8bAac4C443097d697F87CC35C5d6B06dDe64D60',
                    },
                    apiConfiguration: {
                      jsonRpcEvmUrl: 'https://rpc.qtestnet.org',
                      rarimeApiUrl: 'https://api.orgs.app.stage.rarime.com',
                    },
                    userConfiguration: {
                      userPrivateKey: userPrivateKey,
                    },
                  };

                  console.log(rarimeConfig);

                  const rarime = new Rarime(rarimeConfig);

                  const passport = new RarimePassport({
                    dataGroup1: DG1 ? Buffer.from(DG1, 'base64') : Buffer.from(
                        '', 'base64'),
                    sod: SOD ? Buffer.from(SOD, 'base64') : Buffer.from('',
                        'base64'),
                    ...(DG15 && DG15.length > 0
                        ? {dataGroup15: Buffer.from(DG15, 'base64')}
                        : {}),
                  });

                  console.log('passport', passport);

                  const pub_key = passport.getPassportKey();
                  console.log('Pub key: ', pub_key);

                  const liteRegisterResult = await rarime.registerIdentity(
                      passport,
                  );
                  console.log('liteRegisterResult', liteRegisterResult);
                  setBusy(false);
                } catch (e) {
                  console.error(e);
                  alert('Error: ' + (e as Error).message);
                  setBusy(false);
                }
              }}
          />
        </ScrollView>
      </View>
  );
}

const styles = {
  header: {
    fontSize: 30,
    margin: 20,
  },
  groupHeader: {
    fontSize: 20,
    marginBottom: 20,
  },
  group: {
    margin: 20,
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 20,
  },
  container: {
    flex: 1,
    backgroundColor: '#eee',
  },
  view: {
    flex: 1,
    height: 200,
  },
};
