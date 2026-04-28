import { useState } from 'react';
import { Input, Button, Card, Typography, Space } from 'antd';
import {
  ClearOutlined,
} from '@ant-design/icons';

import {
  getUtilsString,
  getUtilsSig,
} from '../apis/api';

const { Text } = Typography;

export default function Tool({ txHash }) {
  const [inputText, setInputText] = useState("");
  const [result, setResult] = useState("");
  const [sig, setSig] = useState("");
  const [pubKey, setPubKey] = useState("");

  const runTransform = async (mode) => {
    try {
      const data = await getUtilsString(inputText, mode);
      setResult(data.result);
      setSig("");
      setPubKey("")
    } catch (err) {
      console.error(err);
    }
  };

  const runGenerateSig = async () => {
    try {
      const data = await getUtilsSig(txHash);
      setResult("");
      setSig(data.sig);
      setPubKey(data.pubKey)
    } catch (err) {
      console.error(err);
    }
  }

  const handleSha256 = async () => {
    await runTransform("sha256");
  }

  const handleHash160 = async () => {
    await runTransform("hash160");
  }

  const handleStr2Hex = async () => {
    await runTransform("str2hex");
  }

  const handleHex2Str = async () => {
    await runTransform("hex2str");
  }

  const handleClearText = () => {
    setInputText("");
    setResult("");
  };

  const handleClearSig = () => {
    setSig("");
    setPubKey("");
  };

  return (
    <Card title="Helper Tools" size="small">
      <Space vertical style={{ width: "100%" }}>
        <Input value={inputText} onChange={e => setInputText(e.target.value)} placeholder="Input text..." style={{ width: "100%" }} />
        <Space size='small' wrap>
          <Button size="small" onClick={handleSha256}>SHA256</Button>
          <Button size="small" onClick={handleHash160}>Hash160</Button>
          <Button size="small" onClick={handleStr2Hex}>Str 2 Hex</Button>
          <Button size="small" onClick={handleHex2Str}>Hex 2 Str</Button>
          <Button size="small" icon={<ClearOutlined />} onClick={handleClearText} />
        </Space>
        {result && <Text copyable code>{result}</Text>}

        <Space size='small' wrap>
          <Button size="small" color="primary" variant="outlined" onClick={runGenerateSig}>Get Random (Sig, PubKey) Pair</Button>
          <Button size="small" icon={<ClearOutlined />} onClick={handleClearSig} />
        </Space>
        {sig && <Text copyable code>{sig}</Text>}
        {pubKey && <Text copyable code>{pubKey}</Text>}
      </Space>
    </Card>
  );
}