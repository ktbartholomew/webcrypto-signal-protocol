const CURVE = "P-256";

declare type FullIdentity = {
  identitySigningKey: CryptoKeyPair;
  identityDHKey: CryptoKeyPair;
  signedPreKey: CryptoKeyPair;
  preKeySignature: string;
  oneTimePreKeys: CryptoKeyPair[];
};

declare type PrekeyBundle = {
  identitySigningKey: CryptoKey;
  identityDHKey: CryptoKey;
  signedPrekey: CryptoKey;
  prekeySignature: string;
  oneTimePrekey?: CryptoKey;
};

declare type PrekeyMessage = {
  identityKey: string;
  ephemeralKey: string;
  preKey: string;
  iv: string;
  message: string;
};

/**
 * These are all global-to-this-module variables to easily share
 * the outputs of some of the crypto operations.
 */
const identities: { [key: string]: FullIdentity } = {};

let bobPrekeyBundle: PrekeyBundle | undefined;

let aliceEphemeralKey: CryptoKeyPair | undefined;

let aliceSymmetricKey: CryptoKey | undefined;

let aliceMessage: PrekeyMessage | undefined;

let bobSymmetricKey: CryptoKey | undefined;

async function aliceFetchBob(e: Event) {
  bobPrekeyBundle = getPrekeyBundle("bob");

  const el = document.getElementById("fetch-bob-prekey-bundle");
  if (el) {
    el.innerHTML = JSON.stringify(
      {
        identityKey: bufferToBase64(
          await crypto.subtle.exportKey(
            "raw",
            bobPrekeyBundle.identitySigningKey
          )
        ),
        signedPrekey: bufferToBase64(
          await crypto.subtle.exportKey("raw", bobPrekeyBundle.signedPrekey)
        ),
        prekeySignature: bobPrekeyBundle.prekeySignature,
        oneTimePrekey: bufferToBase64(
          await crypto.subtle.exportKey(
            "raw",
            bobPrekeyBundle.oneTimePrekey as CryptoKey
          )
        ),
      },
      null,
      2
    );
  }
}

async function aliceValidateBob(e: Event) {
  if (!bobPrekeyBundle) {
    return;
  }

  const verified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    bobPrekeyBundle?.identitySigningKey as CryptoKey,
    base64ToBuffer(bobPrekeyBundle.prekeySignature),
    await crypto.subtle.exportKey("raw", bobPrekeyBundle.signedPrekey)
  );

  const el = document.getElementById("verify-bob-prekey-bundle");
  if (el) {
    el.innerHTML = JSON.stringify({ verified });
  }
}

async function aliceDHCalculations(e: Event) {
  if (!bobPrekeyBundle) {
    await aliceFetchBob(e);
  }

  const alice = identities["alice"];
  const bob = bobPrekeyBundle;

  const ephemeralKey = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: CURVE,
    },
    true,
    ["deriveKey"]
  );

  const dh1 = await crypto.subtle.deriveKey(
    { name: "ECDH", public: bob?.signedPrekey },
    alice.identityDHKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const dh2 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: bob?.identityDHKey,
    },
    ephemeralKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const dh3 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: bob?.signedPrekey,
    },
    ephemeralKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const dh4 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: bob?.oneTimePrekey,
    },
    ephemeralKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const sk = await createX3DHKey(dh1, dh2, dh3, dh4);

  aliceEphemeralKey = ephemeralKey;
  aliceSymmetricKey = sk;

  const el = document.getElementById("alice-generate-sk");
  if (el) {
    const skString = bufferToBase64(await crypto.subtle.exportKey("raw", sk));

    let text = JSON.stringify(
      {
        ek: bufferToBase64(
          await crypto.subtle.exportKey("raw", ephemeralKey.publicKey)
        ),
        d1: bufferToBase64(await crypto.subtle.exportKey("raw", dh1)),
        d2: bufferToBase64(await crypto.subtle.exportKey("raw", dh2)),
        d3: bufferToBase64(await crypto.subtle.exportKey("raw", dh3)),
        d4: bufferToBase64(await crypto.subtle.exportKey("raw", dh4)),
        sk: skString,
      },
      null,
      2
    );

    text = text.replace(
      skString,
      `<span class="text-emphasis-red">${skString}</span>`
    );

    el.innerHTML = text;
  }
}

async function aliceEncryptMessage(e: Event) {
  if (!aliceSymmetricKey) {
    await aliceDHCalculations(e);
  }

  const messageText =
    (document.getElementById("alice-message") as HTMLTextAreaElement).value ??
    "";

  const message = JSON.stringify({
    timestamp: new Date().toISOString(),
    msg: messageText,
  });

  const aliceIdString = bufferToBase64(
    await crypto.subtle.exportKey(
      "raw",
      identities["alice"].identitySigningKey.publicKey
    )
  );
  const bobIdString = bufferToBase64(
    await crypto.subtle.exportKey(
      "raw",
      bobPrekeyBundle?.identitySigningKey as CryptoKey
    )
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(
        `${aliceIdString}|${bobIdString}`
      ),
    },
    aliceSymmetricKey as CryptoKey,
    new TextEncoder().encode(message as string)
  );

  aliceMessage = {
    identityKey: bufferToBase64(
      await crypto.subtle.exportKey(
        "raw",
        identities["alice"].identitySigningKey.publicKey
      )
    ),
    ephemeralKey: bufferToBase64(
      await crypto.subtle.exportKey(
        "raw",
        aliceEphemeralKey?.publicKey as CryptoKey
      )
    ),
    preKey: bufferToBase64(
      await crypto.subtle.exportKey(
        "raw",
        bobPrekeyBundle?.oneTimePrekey as CryptoKey
      )
    ),
    iv: bufferToBase64(iv),
    message: bufferToBase64(encrypted),
  };

  const el = document.getElementById("alice-ciphertext");
  if (el) {
    let text = JSON.stringify(aliceMessage, null, 2);

    text = text.replace(
      aliceMessage.message,
      `<span class="text-emphasis-green">${aliceMessage.message}</span>`
    );

    el.innerHTML = text;
  }
}

async function bobDHCalculations(e: Event) {
  if (!aliceMessage) {
    await aliceEncryptMessage(e);
  }

  const prekeyMessage = aliceMessage;
  const bob = identities["bob"];

  const aliceIdentityKey = await crypto.subtle.importKey(
    "raw",
    base64ToBuffer(prekeyMessage?.identityKey as string),
    { name: "ECDH", namedCurve: CURVE },
    true,
    []
  );

  const ephemeralKey = await crypto.subtle.importKey(
    "raw",
    base64ToBuffer(prekeyMessage?.ephemeralKey as string),
    { name: "ECDH", namedCurve: CURVE },
    true,
    []
  );

  const dh1 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: aliceIdentityKey,
    },
    bob.signedPreKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const dh2 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: ephemeralKey,
    },
    bob.identityDHKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const dh3 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: ephemeralKey,
    },
    bob.signedPreKey.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const dh4 = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: ephemeralKey,
    },
    bob.oneTimePreKeys[0].privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const sk = await createX3DHKey(dh1, dh2, dh3, dh4);
  bobSymmetricKey = sk;

  const el = document.getElementById("bob-generate-sk");
  if (el) {
    const skString = bufferToBase64(await crypto.subtle.exportKey("raw", sk));
    let text = JSON.stringify(
      {
        ek: bufferToBase64(await crypto.subtle.exportKey("raw", ephemeralKey)),
        d1: bufferToBase64(await crypto.subtle.exportKey("raw", dh1)),
        d2: bufferToBase64(await crypto.subtle.exportKey("raw", dh2)),
        d3: bufferToBase64(await crypto.subtle.exportKey("raw", dh3)),
        d4: bufferToBase64(await crypto.subtle.exportKey("raw", dh4)),
        sk: skString,
      },
      null,
      2
    );

    text = text.replace(
      skString,
      `<span class="text-emphasis-red">${skString}</span>`
    );

    el.innerHTML = text;
  }
}

async function bobDecrypt(e: Event): Promise<void> {
  if (!bobSymmetricKey) {
    await bobDHCalculations(e);
  }

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBuffer(aliceMessage?.iv as string),
      additionalData: new TextEncoder().encode(
        `${aliceMessage?.identityKey}|${bufferToBase64(
          await crypto.subtle.exportKey(
            "raw",
            identities["bob"].identitySigningKey.publicKey
          )
        )}`
      ),
    },
    bobSymmetricKey as CryptoKey,
    base64ToBuffer(aliceMessage?.message as string)
  );

  const parsedMessage = JSON.parse(
    new TextDecoder().decode(decrypted).toString()
  );

  const el = document.getElementById("bob-plaintext");
  if (el) {
    let text = JSON.stringify(parsedMessage, null, 2);
    text = text.replace(
      parsedMessage.msg,
      `<span class="text-emphasis-green">${parsedMessage.msg}</span>`
    );

    el.innerHTML = text;
  }
}

// @ts-ignore
window.actions = {
  aliceFetchBob,
  aliceValidateBob,
  aliceDHCalculations,
  aliceEncryptMessage,
  bobDHCalculations,
  bobDecrypt,
} as { [key: string]: (e: Event) => void };

function base64ToBuffer(base64String: string): ArrayBuffer {
  const binaryString = atob(base64String);
  const length = binaryString.length;
  const buffer = new ArrayBuffer(length);
  const uint8Array = new Uint8Array(buffer);

  for (let i = 0; i < length; i++) {
    uint8Array[i] = binaryString.charCodeAt(i);
  }

  return buffer;
}

function bufferToBase64(buffer: ArrayBuffer): string {
  const uint8Array = new Uint8Array(buffer);
  const binaryString = String.fromCharCode.apply(null, uint8Array as any);
  return btoa(binaryString);
}

function splitStringIntoChunks(
  inputString: string,
  chunkSize: number
): string[] {
  const result: string[] = [];
  const length = inputString.length;

  for (let i = 0; i < length; i += chunkSize) {
    result.push(inputString.slice(i, i + chunkSize));
  }

  return result;
}

function getPrekeyBundle(user: string): PrekeyBundle {
  const bundle = {
    identitySigningKey: identities[user].identitySigningKey.publicKey,
    identityDHKey: identities[user].identityDHKey.publicKey,
    signedPrekey: identities[user].signedPreKey.publicKey,
    prekeySignature: identities[user].preKeySignature,
    // TODO: register which one time prekey was actually used, using an index or an ID
    oneTimePrekey: identities[user].oneTimePreKeys[0].publicKey,
  };

  return bundle;
}

async function createIdentityKeys(): Promise<FullIdentity> {
  const identitySigningKey = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: CURVE },
    true,
    ["sign", "verify"]
  );

  // TODO: make a named function
  const exportedSigning = {
    privateKey: await crypto.subtle.exportKey(
      "jwk",
      identitySigningKey.privateKey
    ),
    publicKey: await crypto.subtle.exportKey(
      "jwk",
      identitySigningKey.publicKey
    ),
  };

  exportedSigning.privateKey.key_ops = ["deriveKey"];
  exportedSigning.publicKey.key_ops = [];

  const identityDHKey = {
    privateKey: await crypto.subtle.importKey(
      "jwk",
      exportedSigning.privateKey,
      { name: "ECDH", namedCurve: CURVE },
      true,
      ["deriveKey"]
    ),
    publicKey: await crypto.subtle.importKey(
      "jwk",
      exportedSigning.publicKey,
      { name: "ECDH", namedCurve: CURVE },
      true,
      []
    ),
  } as CryptoKeyPair;

  // END TODO

  const signedPreKey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: CURVE },
    true,
    ["deriveKey"]
  );

  const preKeySignature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identitySigningKey.privateKey,
    await crypto.subtle.exportKey("raw", signedPreKey.publicKey)
  );

  const oneTimePreKeys: CryptoKeyPair[] = [];

  for (let i = 0; i < 256; i++) {
    oneTimePreKeys.push(
      await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: CURVE },
        true,
        ["deriveKey"]
      )
    );
  }

  return {
    identitySigningKey: identitySigningKey,
    identityDHKey: identityDHKey,
    signedPreKey,
    preKeySignature: bufferToBase64(preKeySignature),
    oneTimePreKeys,
  };
}

async function sharePrekeyBundle(name: string, bundle: FullIdentity) {
  let shareable = {
    identityKey: bufferToBase64(
      await crypto.subtle.exportKey("raw", bundle.identitySigningKey.publicKey)
    ),
    signedPreKey: bufferToBase64(
      await crypto.subtle.exportKey("raw", bundle.signedPreKey.publicKey)
    ),
    preKeySignature: bundle.preKeySignature,
    oneTimePreKeys: await Promise.all(
      bundle.oneTimePreKeys.map(async (otpk) =>
        bufferToBase64(await crypto.subtle.exportKey("raw", otpk.publicKey))
      )
    ),
  };

  let pkbEl = document.getElementById(`${name}-prekey-bundle`);
  if (pkbEl) {
    pkbEl.innerText = JSON.stringify(shareable, null, 2);
  }
}

async function createX3DHKey(
  dh1: CryptoKey,
  dh2: CryptoKey,
  dh3: CryptoKey,
  dh4: CryptoKey
): Promise<CryptoKey> {
  const concatenated = new Uint8Array(32 * 4);
  concatenated.set(
    new Uint8Array(await crypto.subtle.exportKey("raw", dh1)),
    32 * 0
  );
  concatenated.set(
    new Uint8Array(await crypto.subtle.exportKey("raw", dh2)),
    32 * 1
  );
  concatenated.set(
    new Uint8Array(await crypto.subtle.exportKey("raw", dh3)),
    32 * 2
  );
  concatenated.set(
    new Uint8Array(await crypto.subtle.exportKey("raw", dh4)),
    32 * 3
  );

  const hkdfMaterial = await crypto.subtle.importKey(
    "raw",
    concatenated,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("WhisperMessage"),
      hash: "SHA-256",
    },
    hkdfMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function main() {
  identities["alice"] = await createIdentityKeys();
  identities["bob"] = await createIdentityKeys();

  await sharePrekeyBundle("alice", identities["alice"]);
  await sharePrekeyBundle("bob", identities["bob"]);
}

main().catch((e) => console.error(e));

export {};
