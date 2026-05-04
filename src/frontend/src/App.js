import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { Layout, Menu } from 'antd';
import { CodeOutlined, SwapOutlined } from '@ant-design/icons';

import BitcoinScriptEditor from './pages/BitcoinScriptEditor';
import UTXOVisualizer from './pages/UTXOVisualizer';

const { Header, Content } = Layout;

export default function App() {
  return (
    <BrowserRouter>
      <Layout style={{ minHeight: '100vh', background: '#141414' }}>
        <Header style={{ display: 'flex', alignItems: 'center', background: '#001529' }}>
          <div style={{ color: 'white', fontSize: '18px', fontWeight: 'bold', marginRight: '40px' }}>
            Bitcoin Tools
          </div>

          <Menu theme="dark" mode="horizontal" defaultSelectedKeys={['1']}>
            <Menu.Item key="1" icon={<CodeOutlined />}>
              <Link to="/">Script Interpreter</Link>
            </Menu.Item>
            <Menu.Item key="2" icon={<SwapOutlined />}>
              <Link to="/visualizer">UTXO Visualizer</Link>
            </Menu.Item>
          </Menu>
        </Header>

        <Content style={{ padding: '24px' }}>
          <Routes>
            <Route path="/" element={<BitcoinScriptEditor />} />
          </Routes>
          <Routes>
            <Route path="/visualizer" element={<UTXOVisualizer />} />
          </Routes>
        </Content>
      </Layout>
    </BrowserRouter>
  );
}