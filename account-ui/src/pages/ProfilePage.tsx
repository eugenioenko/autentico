import React, { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';
import Alert from '../components/Alert';
import { useSettings } from '../context/SettingsContext';

interface ProfileForm {
  username: string;
  email: string;
  given_name: string;
  family_name: string;
  middle_name: string;
  nickname: string;
  phone_number: string;
  picture: string;
  website: string;
  gender: string;
  birthdate: string;
  profile: string;
  locale: string;
  address_street: string;
  address_locality: string;
  address_region: string;
  address_postal_code: string;
  address_country: string;
}

const emptyForm: ProfileForm = {
  username: '',
  email: '',
  given_name: '',
  family_name: '',
  middle_name: '',
  nickname: '',
  phone_number: '',
  picture: '',
  website: '',
  gender: '',
  birthdate: '',
  profile: '',
  locale: '',
  address_street: '',
  address_locality: '',
  address_region: '',
  address_postal_code: '',
  address_country: '',
};

const FieldLabel: React.FC<{ label: string; required?: boolean }> = ({ label, required }) => (
  <label>
    {label}
    {required && <span className="text-theme-danger-bg ml-0.5">*</span>}
  </label>
);

const ProfilePage: React.FC = () => {
  const settings = useSettings();
  const { data: profile, refetch } = useQuery({
    queryKey: ['profile'],
    queryFn: () => api.get('/profile').then((res) => res.data.data),
  });

  const [form, setForm] = useState<ProfileForm>(emptyForm);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (profile) {
      setForm({
        username: profile.username || '',
        email: profile.email || '',
        given_name: profile.given_name || '',
        family_name: profile.family_name || '',
        middle_name: profile.middle_name || '',
        nickname: profile.nickname || '',
        phone_number: profile.phone_number || '',
        picture: profile.picture || '',
        website: profile.website || '',
        gender: profile.gender || '',
        birthdate: profile.birthdate || '',
        profile: profile.profile || '',
        locale: profile.locale || '',
        address_street: profile.address_street || '',
        address_locality: profile.address_locality || '',
        address_region: profile.address_region || '',
        address_postal_code: profile.address_postal_code || '',
        address_country: profile.address_country || '',
      });
    }
  }, [profile]);

  const set = (key: keyof ProfileForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [key]: e.target.value }));

  const handleUpdate = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsUpdating(true);
    try {
      const payload = { ...form };
      if (!settings.allow_username_change) delete (payload as Partial<ProfileForm>).username;
      if (!settings.allow_email_change) delete (payload as Partial<ProfileForm>).email;
      await api.put('/profile', payload);
      setSuccess('Profile updated successfully.');
      refetch();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setError(axiosErr.response?.data?.error_description || 'Failed to update profile.');
    } finally {
      setIsUpdating(false);
    }
  };

  const showGivenName = settings.profile_field_given_name !== 'hidden';
  const showFamilyName = settings.profile_field_family_name !== 'hidden';
  const showMiddleName = settings.profile_field_middle_name !== 'hidden';
  const showNickname = settings.profile_field_nickname !== 'hidden';
  const showPhone = settings.profile_field_phone !== 'hidden';
  const showPicture = settings.profile_field_picture !== 'hidden';
  const showWebsite = settings.profile_field_website !== 'hidden';
  const showGender = settings.profile_field_gender !== 'hidden';
  const showBirthdate = settings.profile_field_birthdate !== 'hidden';
  const showProfileURL = settings.profile_field_profile !== 'hidden';
  const showLocale = settings.profile_field_locale !== 'hidden';
  const showAddress = settings.profile_field_address !== 'hidden';

  const req = (field: string) => settings[`profile_field_${field}` as keyof typeof settings] === 'required';

  return (
    <Card title="Personal Information" description="Update your profile details.">
      <form onSubmit={handleUpdate} className="space-y-5 mt-2">
        <div>
          <label>Username</label>
          {settings.allow_username_change ? (
            <input type="text" value={form.username} onChange={set('username')} />
          ) : (
            <p className="text-sm text-theme-fg py-1">{form.username}</p>
          )}
        </div>
        <div>
          <label>Email Address</label>
          {settings.allow_email_change ? (
            <input type="email" value={form.email} onChange={set('email')} />
          ) : (
            <p className="text-sm text-theme-fg py-1">{form.email || <span className="text-theme-muted">Not set</span>}</p>
          )}
        </div>

        {showGivenName && (
          <div>
            <FieldLabel label="First Name" required={req('given_name')} />
            <input type="text" value={form.given_name} onChange={set('given_name')} required={req('given_name')} />
          </div>
        )}
        {showFamilyName && (
          <div>
            <FieldLabel label="Last Name" required={req('family_name')} />
            <input type="text" value={form.family_name} onChange={set('family_name')} required={req('family_name')} />
          </div>
        )}
        {showMiddleName && (
          <div>
            <FieldLabel label="Middle Name" required={req('middle_name')} />
            <input type="text" value={form.middle_name} onChange={set('middle_name')} required={req('middle_name')} />
          </div>
        )}
        {showNickname && (
          <div>
            <FieldLabel label="Nickname" required={req('nickname')} />
            <input type="text" value={form.nickname} onChange={set('nickname')} required={req('nickname')} />
          </div>
        )}
        {showPhone && (
          <div>
            <FieldLabel label="Phone Number" required={req('phone')} />
            <input type="tel" value={form.phone_number} onChange={set('phone_number')} required={req('phone')} />
          </div>
        )}
        {showPicture && (
          <div>
            <FieldLabel label="Profile Picture URL" required={req('picture')} />
            <input type="url" value={form.picture} onChange={set('picture')} required={req('picture')} />
          </div>
        )}
        {showWebsite && (
          <div>
            <FieldLabel label="Website" required={req('website')} />
            <input type="url" value={form.website} onChange={set('website')} required={req('website')} />
          </div>
        )}
        {showProfileURL && (
          <div>
            <FieldLabel label="Profile Page URL" required={req('profile')} />
            <input type="url" value={form.profile} onChange={set('profile')} required={req('profile')} />
          </div>
        )}
        {showGender && (
          <div>
            <FieldLabel label="Gender" required={req('gender')} />
            <input type="text" value={form.gender} onChange={set('gender')} required={req('gender')} />
          </div>
        )}
        {showBirthdate && (
          <div>
            <FieldLabel label="Birthdate" required={req('birthdate')} />
            <input type="date" value={form.birthdate} onChange={set('birthdate')} required={req('birthdate')} />
          </div>
        )}
        {showLocale && (
          <div>
            <FieldLabel label="Locale" required={req('locale')} />
            <input type="text" placeholder="e.g. en-US" value={form.locale} onChange={set('locale')} required={req('locale')} />
          </div>
        )}
        {showAddress && (
          <>
            <div>
              <FieldLabel label="Street Address" required={req('address')} />
              <input type="text" value={form.address_street} onChange={set('address_street')} required={req('address')} />
            </div>
            <div>
              <FieldLabel label="City" required={req('address')} />
              <input type="text" value={form.address_locality} onChange={set('address_locality')} required={req('address')} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel label="State / Region" required={req('address')} />
                <input type="text" value={form.address_region} onChange={set('address_region')} required={req('address')} />
              </div>
              <div>
                <FieldLabel label="Postal Code" required={req('address')} />
                <input type="text" value={form.address_postal_code} onChange={set('address_postal_code')} required={req('address')} />
              </div>
            </div>
            <div>
              <FieldLabel label="Country" required={req('address')} />
              <input type="text" value={form.address_country} onChange={set('address_country')} required={req('address')} />
            </div>
          </>
        )}

        {error && <Alert type="danger" message={error} />}
        {success && <Alert type="success" message={success} />}

        <div className="flex justify-end">
          <Button type="submit" disabled={isUpdating}>
            {isUpdating ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>
      </form>
    </Card>
  );
};

export default ProfilePage;
