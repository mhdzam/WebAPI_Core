using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using BackendServices.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.AccessControl;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace BackendServices.Controllers
{
   
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly BookStoreContext _context;
        private readonly JWTSettings _JWTToken;

        public UsersController(BookStoreContext context, IOptions<JWTSettings> JwtToken)
        {
            _context = context;
            _JWTToken = JwtToken.Value;
        }

        // POST: api/Users
        [HttpPost("Login")]
        public async Task<ActionResult<UserWithToken>> Login([FromBody] User user)
        {
            user = await _context.User.Include(u => u.Role)
                                        .Where(u => u.EmailAddress == user.EmailAddress
                                                && u.Password == user.Password).
                                                FirstOrDefaultAsync();

            UserWithToken userWithToken = new UserWithToken(user);

          
         
            if (userWithToken == null)
            {
                return NotFound();
            }

            //sing your tokrn here ...
            var tokenhandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_JWTToken.SecretKey);
            var tokeDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name,user.EmailAddress)
                }),
                Expires = DateTime.Now.AddMonths(6),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                 SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenhandler.CreateToken(tokeDescriptor);
            userWithToken.Token = tokenhandler.WriteToken(token);

            return userWithToken;
        }


        // GET: api/Users
        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            return await _context.User.ToListAsync();
        }

        // GET: api/Users/5
        [HttpGet("GetUser")]
        public async Task<ActionResult<User>> GetUser()
        {
            string emailaddress = HttpContext.User.Identity.Name;
            var user = await _context.User.Where(usr => usr.EmailAddress == emailaddress).FirstOrDefaultAsync();

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }

        // PUT: api/Users/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPut("{id}")]
        public async Task<IActionResult> PutUser(int id, User user)
        {
            if (id != user.UserId)
            {
                return BadRequest();
            }

            _context.Entry(user).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/Users
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPost]
        public async Task<ActionResult<User>> PostUser(User user)
        {
            _context.User.Add(user);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetUser", new { id = user.UserId }, user);
        }

        // DELETE: api/Users/5
        [HttpDelete("{id}")]
        public async Task<ActionResult<User>> DeleteUser(int id)
        {
            var user = await _context.User.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            _context.User.Remove(user);
            await _context.SaveChangesAsync();

            return user;
        }

        private bool UserExists(int id)
        {
            return _context.User.Any(e => e.UserId == id);
        }
    }
}
