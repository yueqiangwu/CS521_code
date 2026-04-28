import { List, Card, Typography, Space, Tag, Tooltip } from 'antd';

const { Text } = Typography;

export default function Pipeline({ isInner, instructions, pc }) {
  return (
    <Space vertical style={{ width: "100%" }}>
      <Card title={isInner ? "Instruction Pipeline (Inner VM)" : "Instruction Pipeline"} size="small">
        <List
          dataSource={instructions}
          renderItem={(item, index) => {
            let bgColor = 'transparent';
            if (index < pc) {
              bgColor = '#ccf3c5';
            }
            if (index === pc) {
              bgColor = '#f0e3a3';
            }

            return (
              <List.Item style={{ backgroundColor: bgColor, padding: '5px 10px' }}>
                <Tag color={index === pc ? "gold" : "default"}>Instr {index}</Tag>
                <Tooltip color="#ffffff" title={<Text copyable>{item}</Text>}>
                  <Text strong={index === pc} ellipsis style={{ maxWidth: '300px' }}>{item}</Text>
                </Tooltip>
              </List.Item>
            );
          }}
        />
      </Card>
    </Space>
  );
}