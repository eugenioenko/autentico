import { IconEye, IconEyeOff } from "@tabler/icons-react";
import { IconButton, Input } from "@yarcl/react";
import { useState, type ComponentProps } from "react";

export default function PasswordInput(props: Omit<ComponentProps<typeof Input>, "type">) {
  const [visible, setVisible] = useState(false);
  return (
    <Input
      autoComplete="new-password"
      {...props}
      type={visible ? "text" : "password"}
      endContent={
        <IconButton
          variant="ghost"
          color="neutral"
          aria-label={visible ? "Hide password" : "Show password"}
          aria-pressed={visible}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? <IconEyeOff /> : <IconEye />}
        </IconButton>
      }
    />
  );
}
