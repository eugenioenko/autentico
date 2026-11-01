import { IconSearch, IconX } from "@tabler/icons-react";
import { IconButton, Input } from "@yarcl/react";
import { useState, type ComponentProps } from "react";

type SearchInputProps = Omit<ComponentProps<typeof Input>, "onChange" | "value" | "defaultValue" | "type"> & {
  value?: string;
  onSearch: (value: string) => void;
  onValueChange?: (value: string) => void;
};

export default function SearchInput({ value: valueProp, onSearch, onValueChange, placeholder = "Search", ...props }: SearchInputProps) {
  const [own, setOwn] = useState("");
  const value = valueProp ?? own;
  const change = (next: string) => {
    if (valueProp === undefined) setOwn(next);
    onValueChange?.(next);
  };
  return (
    <Input
      {...props}
      type="search"
      aria-label={props["aria-label"] ?? placeholder}
      placeholder={placeholder}
      value={value}
      onChange={(e) => {
        change(e.target.value);
        if (e.target.value === "") onSearch("");
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSearch(value.trim());
      }}
      startContent={<IconSearch aria-hidden="true" className="search-input-icon" />}
      endContent={
        value ? (
          <IconButton
            variant="ghost"
            color="neutral"
            aria-label="Clear search"
            onClick={() => {
              change("");
              onSearch("");
            }}
          >
            <IconX />
          </IconButton>
        ) : undefined
      }
    />
  );
}
