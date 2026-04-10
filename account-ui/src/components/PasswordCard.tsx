import React, { useState } from 'react';
import Card from './Card';
import Button from './Button';
import PasswordChangeModal from './PasswordChange';

const PasswordCard: React.FC = () => {
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      {showModal && <PasswordChangeModal onClose={() => setShowModal(false)} />}
      <Card
        title="Password"
        description="Change your password to keep your account secure."
        action={
          <Button onClick={() => setShowModal(true)}>
            Change Password
          </Button>
        }
      />
    </>
  );
};

export default PasswordCard;
