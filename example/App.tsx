import { Button, ScrollView, Text, View } from "react-native";
import React from "react";
import { generateQueryProof, getPollsData, liteRegistration } from "./src";

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
            try {
              const txHash = await liteRegistration();
              console.log("txHash", txHash);
              setBusy(false);
            } catch (e) {
              console.error(e);
              alert("Error: " + (e as Error).message);
              setBusy(false);
            }
          }}
        />

        <Button
          title="generate query proof"
          disabled={busy}
          onPress={async () => {
            setBusy(true);
            try {
              const queryProof = await generateQueryProof();
              console.log("queryProof", queryProof);
              setBusy(false);
            } catch (e) {
              console.error(e);
              alert("Error: " + (e as Error).message);
              setBusy(false);
            }
          }}
        />

        <Button
          title="Get proposal data"
          disabled={busy}
          onPress={async () => {
            setBusy(true);
            try {
              const pollsData = await getPollsData();
              console.log("pollsData", pollsData);
              setBusy(false);
            } catch (e) {
              console.error(e);
              alert("Error: " + (e as Error).message);
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
