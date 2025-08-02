class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  validates :username, length: { in: 6..40 }
  validates :email, uniqueness: true, length: { in: 6..100 }
  validates :password, length: { in: 8..30 }
end
