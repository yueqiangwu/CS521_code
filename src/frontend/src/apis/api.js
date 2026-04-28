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

export {
  postInit,
  getTemplatesOptions,
  getTemplates,
  postStep,
  postClear,
  getUtilsString,
  getUtilsSig,
};