using Core.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security;
public class RefreshToken
{
    public Guid Id { get; set; }
    public Guid ApplicationUserId { get; set; }
    public string Code { get; set; }
    public DateTime ExpirationDate { get; set; }
    public ApplicationUser ApplicationUser { get; set; } = null!;
}
