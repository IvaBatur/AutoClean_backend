// AutoClean backend: Express + MongoDB (Mongoose) + JWT
require('dotenv').config({ quiet: true });
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ---------------------------------------------------------------
// Postavke
// ---------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
// Tko se registrira s ovim emailom dobiva ulogu admin (vlasnik)
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
// Adrese frontenda kojima je dopušten pristup (odvojene zarezom)
const CORS_ORIGINS = (process.env.CORS_ORIGIN || 'http://localhost:8080')
  .split(',')
  .map((s) => s.trim());

if (!MONGO_URI || !JWT_SECRET) {
  console.error('Nedostaje MONGO_URI ili JWT_SECRET u .env datoteci.');
  process.exit(1);
}

// Radno vrijeme autopraonice (u minutama od ponoći)
const OPEN_MIN = 8 * 60; // 08:00
const CLOSE_MIN = 18 * 60; // 18:00
const SLOT_STEP = 30; // termini počinju svakih 30 minuta
const BAYS = 1; // koliko vozila se može prati istodobno
const TIME_ZONE = 'Europe/Zagreb';
const STATUSES = ['Zakazano', 'Završeno', 'Otkazano'];

// ---------------------------------------------------------------
// Modeli
// ---------------------------------------------------------------
const User = mongoose.model(
  'User',
  new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['client', 'admin'], default: 'client' }
  })
);

const Service = mongoose.model(
  'Service',
  new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    description: { type: String, default: '', trim: true },
    price: { type: Number, required: true, min: 0 }, // EUR
    duration: { type: Number, required: true, min: 5 } // minute
  })
);

const Reservation = mongoose.model(
  'Reservation',
  new mongoose.Schema(
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      clientEmail: String,
      service: { type: mongoose.Schema.Types.ObjectId, ref: 'Service', required: true },
      serviceName: String,
      date: { type: String, required: true }, // YYYY-MM-DD
      time: { type: String, required: true }, // HH:MM
      startMin: Number, // početak u minutama od ponoći
      endMin: Number, // kraj = početak + trajanje usluge
      status: { type: String, enum: STATUSES, default: 'Zakazano' }
    },
    { timestamps: true }
  )
);

// ---------------------------------------------------------------
// Pomoćne funkcije
// ---------------------------------------------------------------
const isValidDate = (s) => {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
};
const isValidTime = (s) => typeof s === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
const toMin = (t) => {
  const [h, m] = t.split(':').map(Number);
  return h * 60 + m;
};
const toTime = (min) =>
  String(Math.floor(min / 60)).padStart(2, '0') + ':' + String(min % 60).padStart(2, '0');

// Trenutni datum i vrijeme u Hrvatskoj (server na Renderu radi u UTC-u)
function nowInZagreb() {
  const d = new Date();
  return {
    date: d.toLocaleDateString('sv-SE', { timeZone: TIME_ZONE }),
    time: d.toLocaleTimeString('sv-SE', { timeZone: TIME_ZONE, hour: '2-digit', minute: '2-digit' })
  };
}

// Provjera da je termin valjan: format, radno vrijeme, ne u prošlosti.
// Vraća { error } ili { startMin, endMin }.
function checkSlot(date, time, duration) {
  if (!isValidDate(date)) return { error: 'Datum mora biti u obliku GGGG-MM-DD.' };
  if (!isValidTime(time)) return { error: 'Vrijeme mora biti u obliku HH:MM.' };

  const startMin = toMin(time);
  const endMin = startMin + duration;

  if (startMin % SLOT_STEP !== 0) {
    return { error: `Termin mora počinjati svakih ${SLOT_STEP} minuta (npr. 09:00 ili 09:30).` };
  }
  if (startMin < OPEN_MIN || endMin > CLOSE_MIN) {
    return { error: `Termin je izvan radnog vremena (${toTime(OPEN_MIN)} – ${toTime(CLOSE_MIN)}).` };
  }
  const now = nowInZagreb();
  if (date < now.date || (date === now.date && time <= now.time)) {
    return { error: 'Termin ne može biti u prošlosti.' };
  }
  return { startMin, endMin };
}

// Koliko postojećih (neotkazanih) rezervacija se preklapa s terminom.
// Dva termina se preklapaju ako: početakA < krajB  I  krajA > početakB
function countOverlaps(date, startMin, endMin, ignoreId) {
  const filter = {
    date,
    status: { $ne: 'Otkazano' },
    startMin: { $lt: endMin },
    endMin: { $gt: startMin }
  };
  if (ignoreId) filter._id = { $ne: ignoreId };
  return Reservation.countDocuments(filter);
}

// Omogućuje async funkcije u rutama bez try/catch u svakoj
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const isOwnerOrAdmin = (reservation, user) =>
  user.role === 'admin' || String(reservation.user) === user.id;

// ---------------------------------------------------------------
// Autentifikacija i autorizacija (JWT)
// ---------------------------------------------------------------
// Provjerava token iz zaglavlja:  Authorization: Bearer <token>
function auth(req, res, next) {
  const [type, token] = (req.headers.authorization || '').split(' ');
  if (type !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Potrebna je prijava.' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, role }
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token nije valjan ili je istekao.' });
  }
}

// Propušta samo korisnike s navedenom ulogom
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role)
    ? next()
    : res.status(403).json({ message: 'Nemate ovlasti za ovu radnju.' });

// ---------------------------------------------------------------
// Express aplikacija
// ---------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(
  cors({
    origin(origin, callback) {
      // bez origin-a (Postman, Thunder Client) ili s popisa dopuštenih
      if (!origin || CORS_ORIGINS.includes(origin)) return callback(null, true);
      callback(new Error('CORS: adresa nije dopuštena'));
    }
  })
);

app.get('/', (req, res) => res.json({ message: 'AutoClean API radi.' }));

// ---------------------------------------------------------------
// Korisnici: registracija, prijava, profil
// ---------------------------------------------------------------
app.post(
  '/api/register',
  wrap(async (req, res) => {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Ime, email i lozinka su obavezni.' });
    }
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Email nije valjan.' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ message: 'Lozinka mora imati najmanje 6 znakova.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    if (await User.findOne({ email: cleanEmail })) {
      return res.status(409).json({ message: 'Korisnik s tim emailom već postoji.' });
    }

    const hashed = await bcrypt.hash(String(password), 10);
    const role = ADMIN_EMAIL && cleanEmail === ADMIN_EMAIL ? 'admin' : 'client';
    await User.create({ name, email: cleanEmail, password: hashed, role });
    res.status(201).json({ message: 'Registracija uspješna.' });
  })
);

app.post(
  '/api/login',
  wrap(async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: 'Email i lozinka su obavezni.' });
    }
    const user = await User.findOne({ email: String(email).trim().toLowerCase() });
    if (!user || !(await bcrypt.compare(String(password), user.password))) {
      return res.status(401).json({ message: 'Neispravan email ili lozinka.' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: user.role, email: user.email, name: user.name });
  })
);

// Podaci prijavljenog korisnika (bez lozinke)
app.get(
  '/api/me',
  auth,
  wrap(async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'Korisnik nije pronađen.' });
    res.json(user);
  })
);

// ---------------------------------------------------------------
// Usluge (cjenik): čitanje svi, izmjene samo admin
// ---------------------------------------------------------------
app.get(
  '/api/services',
  wrap(async (req, res) => {
    res.json(await Service.find().sort({ price: 1 }));
  })
);

app.get(
  '/api/services/:id',
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Neispravan ID usluge.' });
    }
    const service = await Service.findById(req.params.id);
    if (!service) return res.status(404).json({ message: 'Usluga nije pronađena.' });
    res.json(service);
  })
);

app.post(
  '/api/services',
  auth,
  requireRole('admin'),
  wrap(async (req, res) => {
    const { name, description, price, duration } = req.body || {};
    if (!name || price === undefined || duration === undefined) {
      return res.status(400).json({ message: 'Naziv, cijena i trajanje su obavezni.' });
    }
    const service = await Service.create({ name, description, price, duration });
    res.status(201).json(service);
  })
);

app.put(
  '/api/services/:id',
  auth,
  requireRole('admin'),
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Neispravan ID usluge.' });
    }
    const { name, description, price, duration } = req.body || {};
    const service = await Service.findByIdAndUpdate(
      req.params.id,
      { name, description, price, duration },
      { new: true, runValidators: true, omitUndefined: true }
    );
    if (!service) return res.status(404).json({ message: 'Usluga nije pronađena.' });
    res.json(service);
  })
);

app.delete(
  '/api/services/:id',
  auth,
  requireRole('admin'),
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Neispravan ID usluge.' });
    }
    const active = await Reservation.countDocuments({ service: req.params.id, status: 'Zakazano' });
    if (active > 0) {
      return res
        .status(409)
        .json({ message: 'Usluga se ne može obrisati jer ima zakazanih rezervacija.' });
    }
    const service = await Service.findByIdAndDelete(req.params.id);
    if (!service) return res.status(404).json({ message: 'Usluga nije pronađena.' });
    res.json({ message: 'Usluga obrisana.' });
  })
);

// ---------------------------------------------------------------
// Rezervacije
// ---------------------------------------------------------------

// Slobodni termini za odabrani datum i uslugu (PROVJERA DOSTUPNOSTI)
// Mora biti definirana prije rute /api/reservations/:id
app.get(
  '/api/reservations/availability',
  auth,
  wrap(async (req, res) => {
    const { date, serviceId } = req.query;
    if (!isValidDate(date) || !mongoose.isValidObjectId(serviceId)) {
      return res.status(400).json({ message: 'Potrebni su ispravni date (GGGG-MM-DD) i serviceId.' });
    }
    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ message: 'Usluga nije pronađena.' });

    // sve zauzete rezervacije tog dana učitamo odjednom
    const taken = await Reservation.find({ date, status: { $ne: 'Otkazano' } });
    const slots = [];

    for (let start = OPEN_MIN; start + service.duration <= CLOSE_MIN; start += SLOT_STEP) {
      const end = start + service.duration;
      if (checkSlot(date, toTime(start), service.duration).error) continue; // prošlost itd.
      const overlaps = taken.filter((r) => r.startMin < end && r.endMin > start).length;
      if (overlaps < BAYS) slots.push(toTime(start));
    }
    res.json({ date, serviceId, duration: service.duration, slots });
  })
);

// Popis: klijent vidi samo svoje (povijest), admin vidi sve. Filter: ?status=Zakazano
app.get(
  '/api/reservations',
  auth,
  wrap(async (req, res) => {
    const filter = req.user.role === 'admin' ? {} : { user: req.user.id };
    if (req.query.status) {
      if (!STATUSES.includes(req.query.status)) {
        return res.status(400).json({ message: 'Nepoznat status.' });
      }
      filter.status = req.query.status;
    }
    res.json(await Reservation.find(filter).sort({ date: 1, time: 1 }));
  })
);

// Nova rezervacija (SPRJEČAVANJE DVOSTRUKIH REZERVACIJA)
app.post(
  '/api/reservations',
  auth,
  wrap(async (req, res) => {
    const { serviceId, date, time } = req.body || {};
    if (!mongoose.isValidObjectId(serviceId) || !date || !time) {
      return res.status(400).json({ message: 'Usluga, datum i vrijeme su obavezni.' });
    }
    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ message: 'Usluga nije pronađena.' });

    const slot = checkSlot(date, time, service.duration);
    if (slot.error) return res.status(400).json({ message: slot.error });

    if ((await countOverlaps(date, slot.startMin, slot.endMin)) >= BAYS) {
      return res.status(409).json({ message: 'Odabrani termin je već zauzet.' });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ message: 'Korisnik više ne postoji.' });

    const reservation = await Reservation.create({
      user: user._id,
      clientEmail: user.email,
      service: service._id,
      serviceName: service.name,
      date,
      time,
      startMin: slot.startMin,
      endMin: slot.endMin
    });
    res.status(201).json(reservation);
  })
);

// Izmjena termina ili usluge (vlasnik rezervacije ili admin)
app.put(
  '/api/reservations/:id',
  auth,
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Neispravan ID rezervacije.' });
    }
    const reservation = await Reservation.findById(req.params.id);
    if (!reservation) return res.status(404).json({ message: 'Rezervacija nije pronađena.' });
    if (!isOwnerOrAdmin(reservation, req.user)) {
      return res.status(403).json({ message: 'Možete mijenjati samo svoje rezervacije.' });
    }
    if (reservation.status !== 'Zakazano') {
      return res.status(400).json({ message: 'Mogu se mijenjati samo zakazane rezervacije.' });
    }

    const serviceId = req.body.serviceId || reservation.service;
    const date = req.body.date || reservation.date;
    const time = req.body.time || reservation.time;

    if (!mongoose.isValidObjectId(serviceId)) {
      return res.status(400).json({ message: 'Neispravan ID usluge.' });
    }
    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ message: 'Usluga nije pronađena.' });

    const slot = checkSlot(date, time, service.duration);
    if (slot.error) return res.status(400).json({ message: slot.error });

    // ignoriramo samu sebe, inače bi se rezervacija sudarila sa svojim starim terminom
    if ((await countOverlaps(date, slot.startMin, slot.endMin, reservation._id)) >= BAYS) {
      return res.status(409).json({ message: 'Odabrani termin je već zauzet.' });
    }

    reservation.service = service._id;
    reservation.serviceName = service.name;
    reservation.date = date;
    reservation.time = time;
    reservation.startMin = slot.startMin;
    reservation.endMin = slot.endMin;
    await reservation.save();
    res.json(reservation);
  })
);

// Promjena statusa (samo admin): označi kao Završeno ili Otkazano
app.patch(
  '/api/reservations/:id/status',
  auth,
  requireRole('admin'),
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Neispravan ID rezervacije.' });
    }
    const { status } = req.body || {};
    if (!['Završeno', 'Otkazano'].includes(status)) {
      return res.status(400).json({ message: 'Status može biti Završeno ili Otkazano.' });
    }
    const reservation = await Reservation.findById(req.params.id);
    if (!reservation) return res.status(404).json({ message: 'Rezervacija nije pronađena.' });
    if (reservation.status !== 'Zakazano') {
      return res.status(400).json({ message: 'Status se može mijenjati samo zakazanim rezervacijama.' });
    }
    reservation.status = status;
    await reservation.save();
    res.json(reservation);
  })
);

// Otkazivanje (vlasnik ili admin). Rezervacija ostaje u povijesti sa statusom Otkazano.
app.delete(
  '/api/reservations/:id',
  auth,
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Neispravan ID rezervacije.' });
    }
    const reservation = await Reservation.findById(req.params.id);
    if (!reservation) return res.status(404).json({ message: 'Rezervacija nije pronađena.' });
    if (!isOwnerOrAdmin(reservation, req.user)) {
      return res.status(403).json({ message: 'Možete otkazati samo svoje rezervacije.' });
    }
    if (reservation.status !== 'Zakazano') {
      return res.status(400).json({ message: 'Rezervacija je već završena ili otkazana.' });
    }
    reservation.status = 'Otkazano';
    await reservation.save();
    res.json({ message: 'Rezervacija je otkazana.', reservation });
  })
);

// ---------------------------------------------------------------
// Nepoznate rute i greške
// ---------------------------------------------------------------
app.use((req, res) => res.status(404).json({ message: 'Ruta ne postoji.' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ message: 'Neispravan JSON u zahtjevu.' });
  }
  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: err.message });
  }
  if (err.message && err.message.startsWith('CORS')) {
    return res.status(403).json({ message: 'Pristup s ove adrese nije dopušten.' });
  }
  console.error(err);
  res.status(500).json({ message: 'Greška na poslužitelju.' });
});

// ---------------------------------------------------------------
// Pokretanje: prvo baza, pa server
// ---------------------------------------------------------------
async function seedServices() {
  if ((await Service.countDocuments()) > 0) return;
  await Service.insertMany([
    { name: 'Vanjsko pranje', description: 'Pranje karoserije i sušenje.', price: 12, duration: 30 },
    { name: 'Unutarnje čišćenje', description: 'Usisavanje i čišćenje interijera.', price: 20, duration: 60 },
    { name: 'Kompletno pranje', description: 'Vanjsko pranje i unutarnje čišćenje.', price: 30, duration: 90 }
  ]);
  console.log('Dodane početne usluge.');
}

mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log('Povezano na MongoDB.');
    await seedServices();
    app.listen(PORT, () => console.log(`Server radi na portu ${PORT}`));
  })
  .catch((err) => {
    console.error('Greška pri spajanju na bazu:', err.message);
    process.exit(1);
  });
