from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, IntegerField, PasswordField, FileField, DateTimeField
from wtforms.validators import DataRequired, Optional, NumberRange, ValidationError
from datetime import datetime
from models import ScheduleFrequency

class ScanForm(FlaskForm):
    """Form for initiating a subnet scan"""
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
