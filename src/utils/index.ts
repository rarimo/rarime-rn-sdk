import { BaseBlock } from "asn1js";

export function wrapPem(certBlock: BaseBlock): string {
  const LINE_LENGTH = 64;

  const derBuffer = certBlock.toBER();

  if (!derBuffer || derBuffer.byteLength === 0) {
    throw new Error("Failed to encode ASN.1 block to DER bytes.");
  }

  const derUint8Array = new Uint8Array(derBuffer);
  const base64Content = Buffer.from(derUint8Array).toString("base64");

  let formattedBase64 = "";

  for (let i = 0; i < base64Content.length; i += LINE_LENGTH) {
    const chunk = base64Content.substring(i, i + LINE_LENGTH);
    formattedBase64 += chunk + "\n";
  }

  const pemHeader = "-----BEGIN CERTIFICATE-----";
  const pemFooter = "-----END CERTIFICATE-----";

  const pemString = `${pemHeader}\n${formattedBase64}${pemFooter}`;

  return pemString;
}
