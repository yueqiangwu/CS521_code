import { useEffect } from 'react';
import { Layout, Typography } from 'antd';

import Editor from './components/Editor';

const { Header, Content } = Layout;
const { Title } = Typography;

export default function BitcoinIDE() {
  // eslint-disable-next-line
  useEffect(() => { document.title = "Bitcoin Script Interpreter"; }, []);

  return (
    <Layout style={{ minHeight: '100vh', background: '#141414' }}>
      <Header style={{ background: '#001529', display: 'flex', alignItems: 'center' }}>
        <Title level={3} style={{ color: 'white', margin: 0 }}>Bitcoin Script Visual Interpreter</Title>
      </Header>

      <Content style={{ padding: '20px' }}>
        <Editor />
      </Content>
    </Layout>
  );
}