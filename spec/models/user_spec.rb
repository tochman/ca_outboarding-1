# frozen_string_literal: true

RSpec.describe User, type: :model do
  describe 'Factory' do
    it 'for :coach is valid' do
      expect(create(:coach)).to be_valid
    end

    it 'for :member is valid' do
      expect(create(:member)).to be_valid
    end
  end
  describe 'Database' do
    describe 'table' do
      it { is_expected.to have_db_column :email }
      it { is_expected.to have_db_column :first_name }
      it { is_expected.to have_db_column :last_name }
      it { is_expected.to have_db_column :role }

    end

    describe 'associations' do
    end
  end

  describe 'Instance methods' do
    let(:user_without_name) { create(:member, email: 'no_name@random.com', first_name: nil, last_name: nil) }
    let(:user_with_name) { create(:member, first_name: 'John', last_name: 'Doe') }

    it { is_expected.to respond_to :full_name }
    it { is_expected.to respond_to :display_name }

    describe '#full_name' do
      it 'user with name attributes set returns full name' do
        expect(user_with_name.full_name).to eq 'John Doe'
      end

      it 'user without name attributes set returns false' do
        expect(user_without_name.full_name).to be_falsy
      end
    end

    describe '#display_name' do
      it 'user with name attributes set returns full name' do
        expect(user_with_name.display_name).to eq 'John Doe'
      end

      it 'user without name attributes set returns false' do
        expect(user_without_name.display_name).to eq 'no_name@random.com'
      end
    end

    describe 'roles' do 
      it { is_expected.to respond_to :member! }
      it { is_expected.to respond_to :member? }
      it { is_expected.to respond_to :coach? }
      it { is_expected.to respond_to :coach? }
    end
  end

  describe 'Class methods' do
    it { expect(described_class).to respond_to :member }
  end

end
