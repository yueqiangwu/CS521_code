import axios from "axios";
import { message } from "antd";

// const BASE_URL = "http://localhost:5000/api";
const BASE_URL = "https://cs521-code.onrender.com:5000/api";

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 10 * 1000,
});

api.interceptors.response.use(
  (res) => res.data,
  (error) => {
    let errMsg = "Unknown Error";

    if (error.response) {
      const { data, status } = error.response;
      if (data && data.message) {
        errMsg = data.message;
      } else if (status === 401) {
        errMsg = "Unauthorized";
      }

      if (status >= 400 && status < 500) {
        message.warning(errMsg);
      } else {
        message.error(errMsg);
      }
    } else {
      message.error("Network Error");
    }

    return Promise.reject(error);
  }
);

export default api;