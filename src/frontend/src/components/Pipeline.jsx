import { List, Card, Typography, Space, Tag, Tooltip } from 'antd';

const { Text } = Typography;

export default function Pipeline({ transType, pc, instructions }) {
  let transTypeName = "Legacy";
  switch (transType) {
    case 3:
      transTypeName = "P2SH";
      break;
    case 4:
      transTypeName = "P2WPKH";
      break;
    case 5:
      transTypeName = "P2WSH";
      break;
    case 6:
      transTypeName = "P2TR";
      break;
    default:
      break;
  }

  return (
    <Space vertical style={{ width: "100%" }}>
      <Card title={`Instruction Pipeline (${transTypeName} Mode)`} size="small">
        <List
          dataSource={instructions}
          renderItem={(item, index) => {
            const { instr, instrType } = item;

            let bgColor = 'transparent';
            if (index < pc) {
              bgColor = '#ccf3c5';
            }
            if (index === pc) {
              bgColor = '#f0e3a3';
            }

            let instrTypeName = null;
            switch (instrType) {
              case 0:
                instrTypeName = "Old";
                break;
              case 1:
                instrTypeName = "Script Sig";
                break;
              case 2:
                instrTypeName = "Script Pubkey";
                break;
              case 3:
                instrTypeName = "Redeem Script";
                break;
              case 4:
                instrTypeName = "Witness Script";
                break;
              case 5:
                instrTypeName = "Witness Arg";
                break;
              default:
                instrTypeName = "Unknown";
                break;
            }

            return (
              <List.Item style={{ backgroundColor: bgColor, padding: '5px 10px' }}>
                <Tag color={index === pc ? "gold" : "default"}>Instr {index} ({instrTypeName})</Tag>
                <Tooltip color="#ffffff" title={<Text copyable>{instr}</Text>}>
                  <Text strong={index === pc} ellipsis style={{ maxWidth: '300px' }}>{instr}</Text>
                </Tooltip>
              </List.Item>
            );
          }}
        />
      </Card>
    </Space>
  );
}