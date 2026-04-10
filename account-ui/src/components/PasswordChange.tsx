import React, { useState } from 'react';
import api from '../api';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';
import { extractError } from '../lib/utils';

interface PasswordChangeModalProps {
  onClose: () => void;
}

const PasswordChangeModal: React.FC<PasswordChangeModalProps> = ({ onClose }) => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      await api.post('/password', { current_password: currentPassword, new_password: newPassword });
      setSuccess(true);
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to update password.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (success) {
    return (
      <Modal title="Change Password" onClose={onClose}>
        <div className="space-y-4">
          <Alert type="success" message="Password updated successfully." />
          <Button className="w-full" onClick={onClose}>
            Done
          </Button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Change Password" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label>Current Password</label>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoFocus
          />
        </div>
        <div>
          <label>New Password</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
        </div>
        {error && <Alert type="danger" message={error} />}
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" disabled={isSubmitting || !currentPassword || !newPassword} className="flex-1">
            {isSubmitting ? 'Updating…' : 'Update Password'}
          </Button>
        </div>
      </form>
    </Modal>
  );
};

export default PasswordChangeModal;
