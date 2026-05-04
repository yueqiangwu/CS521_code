

export default function UTXOVisualizer() {
  return (
    <div style={{ width: '100%', height: '800px', overflow: 'hidden' }}>
      <iframe
        src="https://cs521-code.onrender.com"
        title="UTXO Visualizer"
        width="100%"
        height="100%"
        style={{ border: 'none' }}
        allowFullScreen
      />
    </div>
  );
};