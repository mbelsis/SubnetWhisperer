from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, IntegerField, PasswordField, FileField, DateTimeField, HiddenField
from wtforms.validators import DataRequired, Optional, NumberRange, ValidationError
from datetime import datetime
from models import ScheduleFrequency

class ScanForm(FlaskForm):
    """Form for initiating a subnet scan"""
    subnets = TextAreaField('Subnets', validators=[DataRequired()], 
                           description='Enter subnets in CIDR notation (e.g., 192.168.1.0/24) or IP ranges (e.g., 192.168.1.1-192.168.1.10), one per line or comma-separated')
    
    # Authentication Options
    use_credential_sets = BooleanField('Use Saved Credential Sets', default=False,
                                     description='Use saved credential sets instead of entering credentials manually')
    
    credential_sets = SelectField('Credential Sets', validators=[Optional()],
                                 coerce=int,
                                 description='Select saved credential sets to use for this scan')
    
    multiple_credentials = BooleanField('Use Multiple Credential Sets', default=False,
                                      description='Try multiple credential sets in order of priority')
    
    username = StringField('SSH Username', validators=[Optional()])
    
    auth_type = SelectField('Authentication Type', 
                           choices=[
                               ('password', 'Password'), 
                               ('key', 'SSH Key')
                           ],
                           default='password')
    
    password = PasswordField('SSH Password', validators=[Optional()])
    
    private_key = TextAreaField('SSH Private Key', validators=[Optional()],
                              description='Paste your private key here')
    
    sudo_password = PasswordField('Sudo Password', validators=[Optional()],
                                description='Password for sudo commands (optional)')
    
    command_template = SelectField('Command Template', validators=[Optional()],
                                 coerce=int)
    
    custom_commands = TextAreaField('Custom Commands', validators=[Optional()],
                                   description='Enter custom commands to execute, one per line')
    
    collect_server_info = BooleanField('Collect Server Information', default=False)
    
    collect_detailed_info = BooleanField('Collect Detailed Server Profile', default=False,
                                       description='Collect comprehensive server information including network cards, IP addresses, DNS configuration, and running services')
    
    concurrency = IntegerField('Concurrency', validators=[NumberRange(min=1, max=100)], 
                              default=10,
                              description='Number of concurrent SSH connections')
                              
    def validate_username(self, field):
        """Validate that username is provided when not using credential sets"""
        if not self.use_credential_sets.data and not field.data:
            raise ValidationError('Username is required when not using credential sets')
            
    def validate_password(self, field):
        """Validate that password is provided when using password auth and not using credential sets"""
        if not self.use_credential_sets.data and self.auth_type.data == 'password' and not field.data:
            raise ValidationError('Password is required when using password authentication')
            
    def validate_private_key(self, field):
        """Validate that private key is provided when using key auth and not using credential sets"""
        if not self.use_credential_sets.data and self.auth_type.data == 'key' and not field.data:
            raise ValidationError('Private key is required when using key authentication')
            
    def validate_credential_sets(self, field):
        """Validate that credential sets are selected when using credential sets"""
        if self.use_credential_sets.data and field.data == 0:  # 0 is the default "None" option
            raise ValidationError('Please select at least one credential set')

class CommandTemplateForm(FlaskForm):
    """Form for creating/editing command templates"""
    name = StringField('Template Name', validators=[DataRequired()])
    
    description = TextAreaField('Description', validators=[Optional()])
    
    commands = TextAreaField('Commands', validators=[DataRequired()],
                           description='Enter commands to execute, one per line')

class ImportForm(FlaskForm):
    """Form for importing CSV files"""
    csv_file = FileField('CSV File', validators=[DataRequired()])
    
class ScheduledScanForm(FlaskForm):
    """Form for creating/editing scheduled scans"""
    name = StringField('Schedule Name', validators=[DataRequired()])
    
    description = TextAreaField('Description', validators=[Optional()])
    
    # Scan configuration - reuse fields from ScanForm
    subnets = TextAreaField('Subnets', validators=[DataRequired()], 
                           description='Enter subnets in CIDR notation (e.g., 192.168.1.0/24) or IP ranges (e.g., 192.168.1.1-192.168.1.10), one per line or comma-separated')
    
    username = StringField('SSH Username', validators=[DataRequired()])
    
    auth_type = SelectField('Authentication Type', 
                           choices=[
                               ('password', 'Password'), 
                               ('key', 'SSH Key')
                           ],
                           default='password')
    
    password = PasswordField('SSH Password', validators=[Optional()])
    
    private_key = TextAreaField('SSH Private Key', validators=[Optional()],
                              description='Paste your private key here')
    
    command_template = SelectField('Command Template', validators=[Optional()],
                                 coerce=int)
    
    custom_commands = TextAreaField('Custom Commands', validators=[Optional()],
                                   description='Enter custom commands to execute, one per line')
    
    collect_server_info = BooleanField('Collect Server Information', default=False)
    
    collect_detailed_info = BooleanField('Collect Detailed Server Profile', default=False,
                                       description='Collect comprehensive server information including network cards, IP addresses, DNS configuration, and running services')
    
    concurrency = IntegerField('Concurrency', validators=[NumberRange(min=1, max=100)], 
                              default=10,
                              description='Number of concurrent SSH connections')
    
    # Schedule configuration
    schedule_frequency = SelectField('Frequency', 
                                   choices=[
                                       (ScheduleFrequency.HOURLY, 'Hourly'),
                                       (ScheduleFrequency.DAILY, 'Daily'),
                                       (ScheduleFrequency.WEEKLY, 'Weekly'),
                                       (ScheduleFrequency.MONTHLY, 'Monthly'),
                                       (ScheduleFrequency.CUSTOM, 'Custom Interval')
                                   ],
                                   default=ScheduleFrequency.DAILY)
    
    custom_interval_minutes = IntegerField('Custom Interval (minutes)', 
                                         validators=[Optional(), NumberRange(min=5, max=44640)],  # 5 minutes to 31 days
                                         default=60,
                                         description='Enter custom interval in minutes (minimum 5 minutes)')
    
    start_date = DateTimeField('Start Date', 
                             format='%Y-%m-%d %H:%M',
                             validators=[DataRequired()],
                             default=datetime.utcnow)
    
    end_date = DateTimeField('End Date (Optional)', 
                           format='%Y-%m-%d %H:%M',
                           validators=[Optional()],
                           description='Leave blank for no end date')
    
    is_active = BooleanField('Active', default=True,
                           description='Uncheck to disable this scheduled scan temporarily')
    
    def validate_end_date(self, field):
        """Validate that end_date is after start_date if provided"""
        if field.data and self.start_date.data:
            if field.data <= self.start_date.data:
                raise ValidationError('End date must be after start date')
                
    def validate_custom_interval_minutes(self, field):
        """Validate that custom interval is provided when frequency is 'custom'"""
        if self.schedule_frequency.data == ScheduleFrequency.CUSTOM and not field.data:
            raise ValidationError('Custom interval is required when frequency is set to Custom')
            
class CredentialSetForm(FlaskForm):
    """Form for creating/editing credential sets"""
    id = HiddenField('ID')
    
    username = StringField('SSH Username', validators=[DataRequired()])
    
    auth_type = SelectField('Authentication Type', 
                          choices=[
                              ('password', 'Password'), 
                              ('key', 'SSH Key')
                          ],
                          default='password')
    
    password = PasswordField('SSH Password', validators=[Optional()])
    
    private_key = TextAreaField('SSH Private Key', validators=[Optional()],
                              description='Paste your private key here')
    
    sudo_password = PasswordField('Sudo Password', validators=[Optional()],
                                description='Password for sudo commands (optional)')
    
    description = TextAreaField('Description', validators=[Optional()],
                              description='Optional description to help identify this credential set')
    
    priority = IntegerField('Priority', validators=[NumberRange(min=0, max=100)], 
                          default=0,
                          description='Priority for trying this credential (higher numbers = higher priority)')
    
    def validate_password(self, field):
        """Validate that password is provided when auth_type is password"""
        if self.auth_type.data == 'password' and not field.data:
            raise ValidationError('Password is required when using password authentication')
            
    def validate_private_key(self, field):
        """Validate that private key is provided when auth_type is key"""
        if self.auth_type.data == 'key' and not field.data:
            raise ValidationError('Private key is required when using key authentication')
