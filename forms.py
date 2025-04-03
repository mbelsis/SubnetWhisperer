from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, IntegerField, PasswordField, FileField
from wtforms.validators import DataRequired, Optional, NumberRange

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
