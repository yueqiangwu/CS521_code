import api from "./index";

const postInit = () => {
  return api.post(`/init`);
};

const getTemplatesOptions = () => {
  return api.get(`/templates/options`);
};

const getTemplates = (transactionType, txHash) => {
  return api.get(`/templates?transactionType=${transactionType}&txHash=${txHash}`);
};

const postStep = (payload) => {
  return api.post(`/step`, payload);
};

const postClear = (sessionId) => {
  return api.post(`/clear`, { sessionId });
};

const getUtilsString = (inputText, mode) => {
  return api.get(`/utils/string?inputText=${inputText}&mode=${mode}`);
};

const getUtilsSig = (txHash) => {
  return api.get(`/utils/sig?txHash=${txHash}`);
};

const getVisualizerState = () => {
  return api.get("/state");
};

const getVisualizerHistory = () => {
  return api.get("/history");
};

const postTransaction = (payload) => {
  return api.post("/transact", payload);
};

const postCreateMultisig = (payload) => {
  return api.post("/create_multisig", payload);
};

const postResetState = () => {
  return api.post("/reset");
};

export {
  postInit,
  getTemplatesOptions,
  getTemplates,
  postStep,
  postClear,
  getUtilsString,
  getUtilsSig,
  getVisualizerState,
  getVisualizerHistory,
  postTransaction,
  postCreateMultisig,
  postResetState,
};