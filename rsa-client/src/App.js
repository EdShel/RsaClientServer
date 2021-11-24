import axios from 'axios';
import { useState } from 'react';
import { generateRsaKeys, encrypt, decrypt } from './rsa';
import './App.css';

const API_URL = 'http://localhost:5239';

const App = () => {
  const [email, setEmail] = useState('eduard.sheliemietiev@nure.ua');
  const [password, setPassword] = useState('qwerty');
  const [balance, setBalance] = useState(null);
  const [error, setError] = useState(null);

  const handleSaveToServerPress = async (e) => {
    e.preventDefault();
    setBalance(null);
    setError(null);

    const { data: serverPublicKey } = await axios.get(`${API_URL}/publicKey`);

    const {
      publicKey: clientPublicKey,
      privateKey: clientPrivateKey
    } = await generateRsaKeys(1024);

    const plaintext = JSON.stringify({ email, password });
    const plaintextHex = Buffer.from(plaintext, 'utf8').toString('hex');
    const ciphertextHex = encrypt(plaintextHex, serverPublicKey);

    try {
      const balanceResponse = await axios.post(`${API_URL}/login`, {
        publicKey: clientPublicKey,
        content: ciphertextHex
      });
      const balanceCiphertext = balanceResponse.data.content;

      const balancePlaintextHex = decrypt(balanceCiphertext, clientPrivateKey);
      const balancePlaintextJson = Buffer.from(balancePlaintextHex, 'hex').toString('utf8');
      const { balance } = JSON.parse(balancePlaintextJson);

      setBalance(balance);
    } catch (e) {
      if (e.response?.status === 403) {
        setError('Access denied');
      } else {
        setError(e.message);
      }
    }
  };


  return <form className="login-form">
    <h1>RSA-protected form</h1>
    <div className="input-group">
      <label>Email</label>
      <input value={email} onChange={e => setEmail(e.target.value)} />
    </div>
    <div className="input-group">
      <label>Password</label>
      <input value={password} onChange={e => setPassword(e.target.value)} type="password" />
    </div>
    <button onClick={handleSaveToServerPress}>Get my balance</button>
    {balance && <div>
      Your balance is <b>{balance}</b>
    </div>
    }
    {error && <div className="error">
      {error}
    </div>
    }
  </form>
};
export default App;
