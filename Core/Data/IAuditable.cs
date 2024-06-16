using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Data;
public interface IAuditable
{
    string UpdatedBy { get; set; }
    DateTime? LastModified { get; set; }
}