import { Dropdown, type MenuProps } from "antd";
import { GlobalOutlined } from "@ant-design/icons";
import { useTranslation } from "react-i18next";
import { changeLanguage, getCurrentLanguage } from "../i18n";

export default function LanguageSwitcher() {
  const { t } = useTranslation();

  const items: MenuProps["items"] = [
    {
      key: "zh",
      label: "中文",
    },
    {
      key: "en",
      label: "English",
    },
  ];

  const current = getCurrentLanguage();

  const onClick: MenuProps["onClick"] = ({ key }) => {
    changeLanguage(key);
  };

  return (
    <Dropdown
      menu={{ items, onClick }}
      placement="bottomRight"
      trigger={["click"]}
    >
      <span
        style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4 }}
        title={t("language.label")}
      >
        <GlobalOutlined />
        {current === "zh" ? "中文" : "English"}
      </span>
    </Dropdown>
  );
}
