// Vite 前端全局声明：补充构建阶段注入的 REST 与 WebSocket 基础地址类型。
/// <reference types="vite/client" />

// 由 vite.config.ts 的 define 字段注入，运行时不从浏览器环境读取。
declare const __API_BASE_URL__: string;
declare const __WS_BASE_URL__: string;
