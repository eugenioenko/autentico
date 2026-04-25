import { Button } from "antd";
import { SunOutlined, MoonOutlined } from "@ant-design/icons";
import { useTheme } from "../context/ThemeContext";

export default function ThemeToggle() {
  const { mode, toggle } = useTheme();
  return (
    <Button
      type="text"
      icon={mode === "dark" ? <SunOutlined /> : <MoonOutlined />}
      onClick={toggle}
    />
  );
}
