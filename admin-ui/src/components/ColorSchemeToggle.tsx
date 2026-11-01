import { IconDeviceDesktop, IconMoon, IconSun, type Icon } from "@tabler/icons-react";
import { IconButton, Inline, Menu, type MenuProps, type Size } from "@yarcl/react";
import { setTheme, useColorScheme, useThemeChoice, type ThemeChoice } from "../theme";

const choices: { value: ThemeChoice; label: string; icon: Icon }[] = [
  { value: "light", label: "Light", icon: IconSun },
  { value: "dark", label: "Dark", icon: IconMoon },
  { value: "system", label: "System", icon: IconDeviceDesktop },
];

export default function ColorSchemeToggle({ placement = "bottom-end", size }: { placement?: MenuProps["placement"]; size?: Size }) {
  const choice = useThemeChoice();
  const scheme = useColorScheme();
  const current = choices.find((c) => c.value === choice)!;
  const TriggerIcon = scheme === "dark" ? IconMoon : IconSun;
  return (
    <Menu placement={placement}>
      <Menu.Trigger>
        <IconButton size={size} variant="ghost" color="neutral" aria-label={`Color scheme: ${current.label}`}>
          <TriggerIcon aria-hidden="true" />
        </IconButton>
      </Menu.Trigger>
      <Menu.Content aria-label="Color scheme">
        <Menu.RadioGroup aria-label="Color scheme" value={choice} onValueChange={(v) => setTheme(v as ThemeChoice)}>
          {choices.map(({ value, label, icon: ChoiceIcon }) => (
            <Menu.RadioItem key={value} value={value} textValue={label}>
              <Inline gap="sm" wrap={false}>
                <ChoiceIcon aria-hidden="true" />
                {label}
              </Inline>
            </Menu.RadioItem>
          ))}
        </Menu.RadioGroup>
      </Menu.Content>
    </Menu>
  );
}
