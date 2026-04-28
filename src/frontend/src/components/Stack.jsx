import { List, Card, Typography, Space, Tag, Tooltip } from 'antd';

const { Text } = Typography;

export default function Stack({ stack }) {
  return (
    <Space vertical style={{ width: "100%" }}>
      <Card title="Data Stack" size="small">
        <List
          dataSource={stack}
          renderItem={(item, index) => (
            <List.Item style={{ padding: '5px 10px' }}>
              <Tag color="blue">Index {stack.length - 1 - index}</Tag>
              <Tooltip color="#ffffff" title={<Text copyable>{item}</Text>}>
                <Text code ellipsis style={{ maxWidth: '300px' }}>{item}</Text>
              </Tooltip>
            </List.Item>
          )}
        />
      </Card>
    </Space>
  );
}