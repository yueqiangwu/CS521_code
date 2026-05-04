import { useState, useEffect } from 'react';
import {
  Row,
  Col,
  Button,
  Card,
  Form,
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
import VfStack from './VfStack';
import CodeEditor from '../../components/CodeEditor';

import {
  postInit,
  getTemplatesOptions,
  getTemplates,
  postStep,
  postClear,
} from '../../apis/api';

const { Text } = Typography;

export default function BitcoinScriptEditor() {
  const [sessionId, setSessionId] = useState("");
  const [txHash, setTxHash] = useState("");
  const [templatesOptions, setTemplatesOptions] = useState([]);

  const [runMode, setRunMode] = useState(false);
  const [transType, setTransType] = useState(0);
  const [pc, setPc] = useState(0);
  const [isTerminated, setIsTerminated] = useState(false);
  const [isValid, setIsValid] = useState(false);
  const [instructions, setInstructions] = useState([]);
  const [stack, setStack] = useState([]);
  const [altStack, setAltStack] = useState([]);
  const [vfStack, setVfStack] = useState([]);

  const [form] = Form.useForm();

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
      form.setFieldsValue({
        scriptSig: data.scriptSig,
        scriptPubkey: data.scriptPubkey,
        witness: data.witness,
      });
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
        ...form.getFieldValue(),
      };
      const data = await postStep(context);

      setRunMode(true);
      setTransType(data.transType)
      setPc(data.pc);
      setIsTerminated(data.isTerminated);
      setInstructions(data.instructions);
      setIsValid(data.isValid);
      setStack(data.stack);
      setAltStack(data.altStack);
      setVfStack(data.vfStack);

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

  const clearInput = () => {
    form.resetFields();
  };

  const clearOutput = () => {
    setRunMode(false);
    setTransType(0);
    setPc(0);
    setIsTerminated(false);
    setIsValid(false);
    setInstructions([]);
    setStack([]);
    setAltStack([]);
    setVfStack([]);
  };

  const handleClearOutput = async () => {
    await runClear();

    clearOutput();
  };

  const handleClearAll = async () => {
    await runClear();

    clearInput();
    clearOutput();
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

              <Form form={form} layout='vertical' initialValues={{
                scriptSig: "",
                scriptPubkey: "",
                witness: "",
              }}>
                <Form.Item label={<Text strong>ScriptSig</Text>} name="scriptSig">
                  <CodeEditor disabled={runMode} height='120px' />
                </Form.Item>

                <Form.Item label={<Text strong>ScriptPubKey</Text>} name="scriptPubkey">
                  <CodeEditor disabled={runMode} height='180px' />
                </Form.Item>

                <Form.Item label={<Text strong>Witness Data</Text>} name="witness">
                  <CodeEditor disabled={runMode} height='120px' />
                </Form.Item>
              </Form>

              <Space size='small' wrap>
                <Button icon={<FastBackwardOutlined />} onClick={handleReset}>Reset</Button>
                <Button color="primary" variant="dashed" icon={<StepBackwardOutlined />} onClick={handleStepBack}>Step Back</Button>
                <Button type="primary" icon={<StepForwardOutlined />} onClick={handleStepOver}>Step Over</Button>
                <Button color="primary" variant="outlined" icon={<FastForwardOutlined />} onClick={handleRunAll}>Run All</Button>
                <Button color="danger" variant="dashed" icon={<ClearOutlined />} onClick={handleClearOutput}>Clear</Button>
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
              <Space vertical style={{ width: "100%" }}>
                <Stack title="Stack" stack={stack} />
                <Stack title="ALT Stack" stack={altStack} />
                <VfStack title="VF Stack" stack={vfStack} />
              </Space>
            </Col>
          </Row>
        </Space>
      </Col>
    </Row>
  );
}