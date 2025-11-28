import { ScrollView, Text, View } from "react-native";
import { Button } from "react-native";
import React from "react";
import {
  Rarime,
  RarimeConfiguration,
  RarimePassport,
  RarimeUtils,
} from "../src";


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
            setBusy(true);
            const userPrivateKey = RarimeUtils.generateBJJPrivateKey();

            const rarimoConfig: RarimeConfiguration = {
              contractsConfiguration: {
                stateKeeperAddress: "0x12883d5F530AF7EC2adD7cEC29Cf84215efCf4D8",
                registerSimpleContractAddress: "0x1b6ae4b80F0f26DC53731D1d7aA31fc3996B513B",
                poseidonSmtAddress: "0xb8bAac4C443097d697F87CC35C5d6B06dDe64D60",
              },
              apiConfiguration: {
                jsonRpcEvmUrl: "https://rpc.qtestnet.org",
                rarimeApiUrl: "https://api.orgs.app.stage.rarime.com",
              },
              userConfiguration: {
                userPrivateKey: userPrivateKey,
              },
            };

            const rarimo = new Rarime(rarimoConfig);

            const passport = new RarimePassport({
              dataGroup1: Buffer.from(
                ""
              ),
              sod: Buffer.from(
               ""
              ),
            });

            const liteRegisterResult = await rarimo.registerIdentity(passport);
            console.log("liteRegisterResult", liteRegisterResult);
            setBusy(false);
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
    backgroundColor: "#fff",
    borderRadius: 10,
    padding: 20,
  },
  container: {
    flex: 1,
    backgroundColor: "#eee",
  },
  view: {
    flex: 1,
    height: 200,
  },
};
