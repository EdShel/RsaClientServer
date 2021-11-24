import forge from 'node-forge';
const BigInteger = forge.jsbn.BigInteger;

function getProbablePrime(bitsCount) {
    return new Promise((resolve, reject) => {
        forge.prime.generateProbablePrime(bitsCount, (error, number) => {
            if (error) {
                reject(error);
            } else {
                resolve(number);
            }
        });
    });
}

async function randomPrimeNumber(bitsCount) {
    while (true) {
        const probablePrime = await getProbablePrime(bitsCount);
        if (probablePrime.isProbablePrime(20)) {
            return probablePrime;
        }
    }
}

export async function generateRsaKeys(keysLength) {
    // Generate 2 different prime numbers: p, q
    let p, q;
    do {
        p = await randomPrimeNumber(keysLength);
        q = await randomPrimeNumber(keysLength);
    } while (p.equals(q));

    // Modulus
    const n = p.multiply(q);

    // Euler totient function value
    const pMinusOne = p.subtract(BigInteger.ONE);
    const qMinusOne = q.subtract(BigInteger.ONE);
    const eulerTotientFunctionValue = pMinusOne.multiply(qMinusOne);

    // Choose e
    const BigIntegerTwo = new BigInteger('2', 10);
    let e;
    do {
        for (e = await randomPrimeNumber(keysLength);
            !eulerTotientFunctionValue.gcd(e).equals(BigInteger.ONE);
            e = e.add(BigIntegerTwo)) { };
    } while (e.compareTo(eulerTotientFunctionValue) >= 0);

    // Find d
    const d = e.modInverse(eulerTotientFunctionValue); // a part of the private key

    const eHex = e.toString(16);
    const nHex = n.toString(16);
    const dHex = d.toString(16);
    return {
        publicKey: {
            e: eHex,
            n: nHex
        },
        privateKey: {
            d: dHex,
            n: nHex
        }
    };
}

export function encrypt(plaintextHex, publicKey) {
    const plaintextNumber = new BigInteger(plaintextHex, 16);
    const e = new BigInteger(publicKey.e, 16);
    const n = new BigInteger(publicKey.n, 16);
    const cyphertext = plaintextNumber.modPow(e, n);
    return bigIntegerToHex(cyphertext);
}

export function decrypt(cyphertextHex, privateKey) {
    const cyphertextNumber = new BigInteger(cyphertextHex, 16);
    const d = new BigInteger(privateKey.d, 16);
    const n = new BigInteger(privateKey.n, 16);
    const plaintext = cyphertextNumber.modPow(d, n);
    return bigIntegerToHex(plaintext);
}

function bigIntegerToHex(bigInt) {
    const hex = bigInt.toString(16);
    if ((hex.length % 2) === 0) {
        return hex;
    }
    return '0' + hex;
}