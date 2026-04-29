import { useState, useEffect } from 'react';
import {
  Row,
  Col,
  Input,
  Button,
  Card,
  Typography,
  Space,
  notification,
} from 'antd';
import {
  ClearOutlined,
  FastBackwardOutlined,
  FastForwardOutlined,
  StepBackwardOutlined,
  StepForwardOutlined,
  ReloadOutlined,
} from '@ant-design/icons';

import Pipeline from './Pipeline';
import Stack from './Stack';
import Tool from './Tool';

import {
  postInit,
  getTemplatesOptions,
  getTemplates,
  postStep,
  postClear,
} from '../apis/api';

const { Text } = Typography;
const { TextArea } = Input;

export default function BSEditor() {
  const [sessionId, setSessionId] = useState("");
  const [txHash, setTxHash] = useState("");
  const [templatesOptions, setTemplatesOptions] = useState([]);

  const [scriptSig, setScriptSig] = useState("");
  const [scriptPubkey, setScriptPubkey] = useState("");
  const [witness, setWitness] = useState("");

  const [runMode, setRunMode] = useState(false);
  const [transType, setTransType] = useState(0);
  const [pc, setPc] = useState(0);
  const [isTerminated, setIsTerminated] = useState(false);
  const [isValid, setIsValid] = useState(false);
  const [instructions, setInstructions] = useState([]);
  const [stack, setStack] = useState([]);

  const [notificationApi, contextHolder] = notification.useNotification();

  const openNotification = (result) => {
    if (result) {
      notificationApi.success({
        title: 'Transaction Success',
        description: 'Please click [Clear All] button to start a new transaction.',
        showProgress: true,
        pauseOnHover: true,
      });
    } else {
      notificationApi.error({
        title: 'Transaction Failed',
        description: 'Please click [Clear All] button to start a new transaction.',
        showProgress: true,
        pauseOnHover: true,
      });
    }
  };

  // eslint-disable-next-line
  useEffect(() => { initEditor(); }, []);

  const initEditor = () => {
    runInit();
    fetchTemplatesOptions();
  };

  const runInit = async () => {
    try {
      const data = await postInit();
      setSessionId(data.sessionId);
      setTxHash(data.txHash);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchTemplatesOptions = async () => {
    try {
      const data = await getTemplatesOptions();
      setTemplatesOptions(data.templatesOptions);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchTemplates = async (transactionType) => {
    try {
      const data = await getTemplates(transactionType, txHash);
      setScriptSig(data.scriptSig);
      setScriptPubkey(data.scriptPubkey);
      setWitness(data.witness);
    } catch (err) {
      console.error(err);
    }
  };

  const runStep = async (mode) => {
    if (isTerminated && mode !== -10 && mode !== -1) {
      openNotification(isValid);
      return;
    };

    try {
      const context = runMode ? { sessionId, mode } : {
        sessionId,
        mode,
        txHash,
        scriptSig,
        scriptPubkey,
        witness,
      };
      const data = await postStep(context);

      setRunMode(true);
      setTransType(data.transType)
      setPc(data.pc);
      setIsTerminated(data.isTerminated);
      setInstructions(data.instructions);
      setIsValid(data.isValid);
      setStack(data.stack);

      if (data.isTerminated) {
        openNotification(data.isValid);
      };
    } catch (err) {
      console.error(err);
    }
  };

  const runClear = async () => {
    try {
      await postClear(sessionId);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRefreshTx = async () => {
    await handleClearAll();
    await runInit();
  };

  const handleLoadTemplate = async (transactionType) => {
    await handleClearAll();
    await fetchTemplates(transactionType);
  };

  const MODE = {
    reset: -10,
    stepBack: -1,
    stepOver: 1,
    runAll: 10,
  };

  const handleReset = async () => {
    await runStep(MODE.reset);
  };

  const handleStepBack = async () => {
    await runStep(MODE.stepBack);
  };

  const handleStepOver = async () => {
    await runStep(MODE.stepOver);
  };

  const handleRunAll = async () => {
    await runStep(MODE.runAll);
  };

  const handleClearAll = async () => {
    await runClear();

    setScriptSig("");
    setScriptPubkey("");
    setWitness("");

    setRunMode(false);
    setTransType(0);
    setPc(0);
    setIsTerminated(false);
    setIsValid(false);
    setInstructions([]);
    setStack([]);
  };

  return (
    <Row gutter={16}>
      <Col span={10}>
        {contextHolder}

        <Space vertical style={{ width: "100%" }}>
          <Card title="Conext" size="small">
            <Space wrap>
              <Text strong>Current TxHash:</Text>
              <Text code copyable>{txHash}</Text>
              <Button color="primary" variant="outlined" size="small" icon={<ReloadOutlined />} onClick={handleRefreshTx} />
            </Space>
          </Card>

          <Card title="Script Editor" size="small">
            <Space vertical style={{ width: "100%" }}>
              <Space size='small' wrap>
                <Text strong>Templates:</Text>
                {(templatesOptions || []).map(item => (
                  <Button size="small" onClick={async () => handleLoadTemplate(item)} >{item}</Button>
                ))}
              </Space>

              <Text strong>ScriptSig</Text>
              <TextArea rows={6} disabled={runMode} value={scriptSig} onChange={e => setScriptSig(e.target.value)} />
              <Text strong>ScriptPubKey</Text>
              <TextArea rows={8} disabled={runMode} value={scriptPubkey} onChange={e => setScriptPubkey(e.target.value)} />
              <Text strong>Witness Data</Text>
              <TextArea rows={4} disabled={runMode} value={witness} onChange={e => setWitness(e.target.value)} />

              <Space size='small' wrap>
                <Button icon={<FastBackwardOutlined />} onClick={handleReset}>Reset</Button>
                <Button color="primary" variant="dashed" icon={<StepBackwardOutlined />} onClick={handleStepBack}>Step Back</Button>
                <Button type="primary" icon={<StepForwardOutlined />} onClick={handleStepOver}>Step Over</Button>
                <Button color="primary" variant="outlined" icon={<FastForwardOutlined />} onClick={handleRunAll}>Run All</Button>
                <Button icon={<ClearOutlined />} danger onClick={handleClearAll}>Clear All</Button>
              </Space>
            </Space>
          </Card>
        </Space>
      </Col>

      <Col span={14}>
        <Space vertical style={{ width: "100%" }}>
          <Tool txHash={txHash} />

          <Row gutter={16}>
            <Col span={13}>
              <Pipeline transType={transType} pc={pc} instructions={instructions} />
            </Col>

            <Col span={11}>
              <Stack stack={stack} />
            </Col>
          </Row>
        </Space>
      </Col>
    </Row>
  );
}