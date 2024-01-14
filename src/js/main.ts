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

interface Window {
  actions: any;
}

const identities: { [key: string]: FullIdentity } = {};

let bobPrekeyBundle: PrekeyBundle | undefined;

// @ts-ignore
window.actions = {
  aliceFetchBob: async (e: Event) => {
    bobPrekeyBundle = getPrekeyBundle("bob");

    console.log(bobPrekeyBundle);

    const el = document.getElementById("fetch-bob-prekey-bundle");
    if (el) {
      el.innerHTML = JSON.stringify(
        {
          identitySigningKey: await crypto.subtle.exportKey(
            "jwk",
            bobPrekeyBundle.identitySigningKey
          ),
          identityDHKey: await crypto.subtle.exportKey(
            "jwk",
            bobPrekeyBundle.identityDHKey
          ),
          signedPrekey: await crypto.subtle.exportKey(
            "jwk",
            bobPrekeyBundle.signedPrekey
          ),
          prekeySignature: bobPrekeyBundle.prekeySignature,
          oneTimePrekey: await crypto.subtle.exportKey(
            "jwk",
            bobPrekeyBundle.oneTimePrekey as CryptoKey
          ),
        },
        null,
        2
      );
    }
  },
  aliceValidateBob: async (e: Event) => {
    if (!bobPrekeyBundle) {
      return;
    }

    const data = new TextEncoder().encode(
      JSON.stringify(
        await crypto.subtle.exportKey("jwk", bobPrekeyBundle.signedPrekey)
      )
    );

    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      bobPrekeyBundle?.identitySigningKey as CryptoKey,
      base64ToBuffer(bobPrekeyBundle.prekeySignature),
      data
    );

    const el = document.getElementById("validate-bob-prekey-bundle");
    if (el) {
      el.innerHTML = JSON.stringify({ verified });
    }
  },
  aliceDHCalculations: async (e: Event) => {
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

    const dhKeys: string[] = [];
    dhKeys.push(
      (await crypto.subtle.exportKey("jwk", dh1)).k ?? "",
      (await crypto.subtle.exportKey("jwk", dh2)).k ?? "",
      (await crypto.subtle.exportKey("jwk", dh3)).k ?? "",
      (await crypto.subtle.exportKey("jwk", dh4)).k ?? ""
    );

    const el = document.getElementById("alice-generate-sk");
    if (el) {
      el.innerHTML = JSON.stringify(
        {
          dh1: (await crypto.subtle.exportKey("jwk", dh1)).k ?? "",
          dh2: (await crypto.subtle.exportKey("jwk", dh2)).k ?? "",
          dh3: (await crypto.subtle.exportKey("jwk", dh3)).k ?? "",
          dh4: (await crypto.subtle.exportKey("jwk", dh4)).k ?? "",
        },
        null,
        2
      );
    }
  },
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

function getPrekeyBundle(user: string): PrekeyBundle {
  const bundle = {
    identitySigningKey: identities[user].identitySigningKey.publicKey,
    identityDHKey: identities[user].identityDHKey.publicKey,
    signedPrekey: identities[user].signedPreKey.publicKey,
    prekeySignature: identities[user].preKeySignature,
    oneTimePrekey: identities[user].oneTimePreKeys.shift()?.publicKey,
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
    new TextEncoder().encode(
      JSON.stringify(
        await crypto.subtle.exportKey("jwk", signedPreKey.publicKey)
      )
    )
  );
  // const preKeySignature = new ArrayBuffer(32);

  /**
   * @type {CryptoKeyPair[]}
   */
  const oneTimePreKeys = [];

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
    preKeySignature: btoa(
      // @ts-ignore
      String.fromCharCode.apply(null, new Uint8Array(preKeySignature))
    ),
    oneTimePreKeys,
  };
}

/**
 * Creates an ECDH keypair using the exact same key material as the provided ECDSA keypair.
 * This is needed because the WebCrypto API will only allow the same key to be used for ECDSA
 * or ECDH, but not both.
 *
 * @param identitySigningKey
 */
async function createIdentityDHKey(
  identitySigningKey: CryptoKeyPair
): Promise<CryptoKeyPair> {}

async function sharePrekeyBundle(name: string, bundle: FullIdentity) {
  let shareable = {
    identitySigningKey: await crypto.subtle.exportKey(
      "jwk",
      bundle.identitySigningKey.publicKey
    ),
    identityDHKey: await crypto.subtle.exportKey(
      "jwk",
      bundle.identityDHKey.publicKey
    ),
    signedPreKey: await crypto.subtle.exportKey(
      "jwk",
      bundle.signedPreKey.publicKey
    ),
    preKeySignature: bundle.preKeySignature,
    oneTimePreKeys: await Promise.all(
      bundle.oneTimePreKeys.map((otpk) =>
        crypto.subtle.exportKey("jwk", otpk.publicKey)
      )
    ),
  };

  let pkbEl = document.getElementById(`${name}-prekey-bundle`);
  if (pkbEl) {
    pkbEl.innerText = JSON.stringify(shareable, null, 2);
  }
}

async function main() {
  identities["alice"] = await createIdentityKeys();
  identities["bob"] = await createIdentityKeys();

  await sharePrekeyBundle("alice", identities["alice"]);
  await sharePrekeyBundle("bob", identities["bob"]);
}

main().catch((e) => console.error(e));

export {};
