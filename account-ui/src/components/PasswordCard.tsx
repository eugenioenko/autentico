import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import Card from './Card';
import Button from './Button';
import PasswordChangeModal from './PasswordChange';

const PasswordCard: React.FC = () => {
  const { t } = useTranslation();
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      {showModal && <PasswordChangeModal onClose={() => setShowModal(false)} />}
      <Card
        title={t('security.password')}
        description={t('security.changePasswordDescription')}
        action={
          <Button onClick={() => setShowModal(true)}>
            {t('profile.changePassword')}
          </Button>
        }
      />
    </>
  );
};

export default PasswordCard;
