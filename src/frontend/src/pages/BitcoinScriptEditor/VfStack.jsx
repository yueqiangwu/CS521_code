import { List, Card, Collapse, Space, Tag } from 'antd';

export default function VfStack({ title, stack }) {
  const data = [{
    key: '1',
    children: (
      <List
        dataSource={stack}
        renderItem={(item, index) => (
          <List.Item style={{ padding: '5px 10px' }}>
            <Tag color="blue">Index {index}</Tag>

            {item ? <Tag color="green">True</Tag> : <Tag color="red">False</Tag>}
          </List.Item>
        )}
      />
    ),
  }];

  return (
    <Space vertical style={{ width: "100%" }}>
      <Card title={title} size="small">
        <Collapse size="small" items={data} />
      </Card>
    </Space>
  );
}