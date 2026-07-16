// Dashboard 前端构建配置：注入本地 REST/WebSocket 地址并限定开发服务器监听范围。

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 允许通过环境变量覆盖端口和 BFF 地址，默认保持全部服务仅本机可见。
const webPort = Number(process.env.DASHBOARD_WEB_PORT || 5173);
const apiPort = Number(process.env.DASHBOARD_API_PORT || 5174);
const apiBaseUrl = process.env.VITE_API_BASE_URL || `http://127.0.0.1:${apiPort}`;
const wsBaseUrl = process.env.VITE_WS_BASE_URL || `ws://127.0.0.1:${apiPort}`;

// 编译期常量让 React 无需读取或暴露服务端环境配置。
export default defineConfig({
  plugins: [react()],
  define: {
    __API_BASE_URL__: JSON.stringify(apiBaseUrl),
    __WS_BASE_URL__: JSON.stringify(wsBaseUrl)
  },
  server: {
    host: "127.0.0.1",
    port: webPort
  },
  build: {
    // React 首屏、Dashboard 业务和图表引擎拆包，降低首次脚本下载与解析的阻塞时间。
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "react-runtime",
              test: /node_modules[\\/](?:react|react-dom|scheduler)[\\/]/,
              priority: 20
            },
            {
              name: "chart-runtime",
              test: /node_modules[\\/](?:recharts|victory-vendor|react-is|d3-[^\\/]+)[\\/]/,
              priority: 10
            }
          ]
        }
      }
    }
  }
});
