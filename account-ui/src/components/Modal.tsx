import React from 'react';
import { IconX } from '@tabler/icons-react';

interface ModalProps {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}

const Modal: React.FC<ModalProps> = ({ title, children, onClose }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
    <div className="bg-theme-bg rounded-2xl shadow-xl w-full max-w-sm">
      <div className="flex items-center justify-between px-6 py-4 border-b border-theme-fg/10">
        <h2 className="text-base font-semibold">{title}</h2>
        <button onClick={onClose} className="text-theme-muted hover:text-theme-fg transition-colors">
          <IconX size={18} />
        </button>
      </div>
      <div className="px-6 py-5">{children}</div>
    </div>
  </div>
);

export default Modal;
